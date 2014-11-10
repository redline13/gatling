/**
 * Copyright 2011-2014 eBusiness Information, Groupe Excilys (www.ebusinessinformation.fr)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gatling.http.fetch

import com.ning.http.client.Request
import com.ning.http.client.uri.Uri
import io.gatling.http.request._
import io.gatling.http.util.HttpHelper._

import scala.annotation.tailrec
import scala.collection.breakOut
import scala.collection.mutable

import com.typesafe.scalalogging.StrictLogging
import io.gatling.core.akka.BaseActor
import io.gatling.core.filter.Filters
import io.gatling.core.result.message.{ OK, Status }
import io.gatling.core.session._
import io.gatling.core.util.TimeHelper.nowMillis
import io.gatling.core.util.cache._
import io.gatling.core.validation._
import io.gatling.http.action.{ RequestAction, HttpRequestAction }
import io.gatling.http.ahc.HttpTx
import io.gatling.http.cache.CacheHandling
import io.gatling.http.config.HttpProtocol
import io.gatling.http.response._

sealed trait ResourceFetched {
  def uri: Uri
  def status: Status
  def sessionUpdates: Session => Session
}
case class RegularResourceFetched(uri: Uri, status: Status, sessionUpdates: Session => Session, silent: Boolean) extends ResourceFetched
case class CssResourceFetched(uri: Uri, status: Status, sessionUpdates: Session => Session, silent: Boolean, statusCode: Option[Int], lastModifiedOrEtag: Option[String], content: String) extends ResourceFetched

case class InferredPageResources(expire: String, requests: List[HttpRequest])

object ResourceFetcher extends StrictLogging {

  // FIXME should CssContentCache use the same key?
  case class InferredResourcesCacheKey(protocol: HttpProtocol, uri: Uri)
  val CssContentCache = new ThreadSafeCache[Uri, List[EmbeddedResource]]("CssContentCache")
  val InferredResourcesCache = new ThreadSafeCache[InferredResourcesCacheKey, InferredPageResources]("InferredResourcesCache")
  //val CssContentCache = ThreadSafeCache[Uri, List[EmbeddedResource]](configuration.http.fetchedCssCacheMaxCapacity)
  //val InferredResourcesCache = ThreadSafeCache[InferredResourcesCacheKey, InferredPageResources](configuration.http.fetchedHtmlCacheMaxCapacity)

  private def applyResourceFilters(resources: List[EmbeddedResource], filters: Option[Filters]): List[EmbeddedResource] =
    filters match {
      case Some(f) => f.filter(resources)
      case none    => resources
    }

  private def resourcesToRequests(resources: List[EmbeddedResource], session: Session, protocol: HttpProtocol, throttled: Boolean): List[HttpRequest] =
    resources.flatMap {
      _.toRequest(session, protocol, throttled) match {
        case Success(httpRequest) => Some(httpRequest)
        case Failure(m) =>
          // shouldn't happen, only static values
          logger.error("Could build request for embedded resource: " + m)
          None
      }
    }

  private def inferPageResources(request: Request, response: Response, session: Session, config: HttpRequestConfig): List[HttpRequest] = {

    val htmlDocumentUri = response.request.getUri
    val protocol = config.protocol

      def inferredResourcesRequests(): List[HttpRequest] = {
        val inferred = new HtmlParser().getEmbeddedResources(htmlDocumentUri, response.body.string, UserAgent.getAgent(request))
        val filtered = applyResourceFilters(inferred, protocol.responsePart.htmlResourcesInferringFilters)
        resourcesToRequests(filtered, session, protocol, config.throttled)
      }

    response.statusCode match {
      case Some(200) =>
        response.lastModifiedOrEtag(protocol) match {
          case Some(newLastModifiedOrEtag) =>
            val cacheKey = InferredResourcesCacheKey(protocol, htmlDocumentUri)
            InferredResourcesCache.cache.get(cacheKey) match {
              case Some(InferredPageResources(`newLastModifiedOrEtag`, res)) =>
                //cache entry didn't expire, use it
                res
              case _ =>
                // cache entry missing or expired, update it
                val inferredResources = inferredResourcesRequests()
                // FIXME add throttle to cache key?
                InferredResourcesCache.cache.put(cacheKey, InferredPageResources(newLastModifiedOrEtag, inferredResources))
                inferredResources
            }

          case None =>
            // don't cache
            inferredResourcesRequests()
        }

      case Some(304) =>
        // no content, retrieve from cache if exist
        InferredResourcesCache.cache.get(InferredResourcesCacheKey(protocol, htmlDocumentUri)) match {
          case Some(inferredPageResources) => inferredPageResources.requests
          case _ =>
            logger.warn(s"Got a 304 for $htmlDocumentUri but could find cache entry?!")
            Nil
        }

      case _ => Nil
    }
  }

  private def buildExplicitResources(resources: List[HttpRequestDef], session: Session): List[HttpRequest] = resources.flatMap { resource =>

    resource.requestName(session) match {
      case Success(requestName) => resource.build(requestName, session) match {
        case Success(httpRequest) =>
          Some(httpRequest)

        case Failure(m) =>
          RequestAction.reportUnbuildableRequest(requestName, session, m)
          None
      }

      case Failure(m) =>
        logger.error("Could build request name for explicitResource: " + m)
        None
    }
  }

  private def resourceFetcher(tx: HttpTx, inferredResources: List[HttpRequest], explicitResources: List[HttpRequest]) = {

    // explicit resources have precedence over implicit ones, so add them last to the Map
    val uniqueResources: Map[Uri, HttpRequest] = (inferredResources ::: explicitResources).map(res => res.ahcRequest.getUri -> res)(breakOut)

    if (uniqueResources.isEmpty)
      None
    else {
      Some(() => new ResourceFetcher(tx, uniqueResources.values.toSeq))
    }
  }

  def resourceFetcherForCachedPage(htmlDocumentURI: Uri, tx: HttpTx): Option[() => ResourceFetcher] = {

    val inferredResources =
      InferredResourcesCache.cache.get(InferredResourcesCacheKey(tx.request.config.protocol, htmlDocumentURI)) match {
        case None            => Nil
        case Some(resources) => resources.requests
      }

    val explicitResources = buildExplicitResources(tx.request.config.explicitResources, tx.session)

    resourceFetcher(tx, inferredResources, explicitResources)
  }

  def resourceFetcherForFetchedPage(request: Request, response: Response, tx: HttpTx): Option[() => ResourceFetcher] = {

    val protocol = tx.request.config.protocol

    val explicitResources =
      if (tx.request.config.explicitResources.nonEmpty)
        ResourceFetcher.buildExplicitResources(tx.request.config.explicitResources, tx.session)
      else
        Nil

    val inferredResources =
      if (protocol.responsePart.inferHtmlResources && response.isReceived && isHtml(response.headers))
        ResourceFetcher.inferPageResources(request, response, tx.session, tx.request.config)
      else
        Nil

    resourceFetcher(tx, inferredResources, explicitResources)
  }
}

// FIXME handle crash
class ResourceFetcher(primaryTx: HttpTx, initialResources: Seq[HttpRequest]) extends BaseActor {

  import ResourceFetcher._

  // immutable state
  val protocol = primaryTx.request.config.protocol
  val throttled = primaryTx.request.config.throttled
  val filters = protocol.responsePart.htmlResourcesInferringFilters

  // mutable state
  var session = primaryTx.session
  val alreadySeen = mutable.Set.empty[Uri]
  val bufferedResourcesByHost = mutable.HashMap.empty[String, List[HttpRequest]].withDefaultValue(Nil)
  val availableTokensByHost = mutable.HashMap.empty[String, Int].withDefaultValue(protocol.enginePart.maxConnectionsPerHost)
  var pendingResourcesCount = 0
  var okCount = 0
  var koCount = 0
  val start = nowMillis

  // start fetching
  fetchOrBufferResources(initialResources)

  private def fetchResource(resource: HttpRequest): Unit = {
    logger.debug(s"Fetching resource ${resource.ahcRequest.getUri}")

    val resourceTx = primaryTx.copy(
      session = this.session,
      request = resource,
      responseBuilderFactory = ResponseBuilder.newResponseBuilderFactory(resource.config.checks, None, protocol.responsePart.discardResponseChunks, protocol.responsePart.inferHtmlResources),
      next = self,
      primary = false)

    HttpRequestAction.startHttpTransaction(resourceTx)
  }

  private def handleCachedResource(resource: HttpRequest): Unit = {

    val uri = resource.ahcRequest.getUri

    logger.info(s"Fetching resource $uri from cache")
    // FIXME check if it's a css this way or use the Content-Type?

    val silent = HttpTx.silent(resource, false)

    val resourceFetched =
      if (CssContentCache.cache.contains(uri))
        CssResourceFetched(uri, OK, Session.Identity, silent, None, None, "")
      else
        RegularResourceFetched(uri, OK, Session.Identity, silent)

    // mock like we've received the resource
    receive(resourceFetched)
  }

  private def fetchOrBufferResources(resources: Iterable[HttpRequest]): Unit = {

      def fetchResources(host: String, resources: Iterable[HttpRequest]): Unit = {
        resources.foreach(fetchResource)
        availableTokensByHost += host -> (availableTokensByHost(host) - resources.size)
      }

      def bufferResources(host: String, resources: Iterable[HttpRequest]): Unit =
        bufferedResourcesByHost += host -> (bufferedResourcesByHost(host) ::: resources.toList)

    alreadySeen ++= resources.map(_.ahcRequest.getUri)
    pendingResourcesCount += resources.size

    val (cached, nonCached) = resources.partition { resource =>
      val uri = resource.ahcRequest.getUri
      CacheHandling.getExpire(protocol, session, uri) match {
        case None => false
        case Some(expire) if nowMillis > expire =>
          // beware, side effecting
          session = CacheHandling.clearExpire(session, uri)
          false
        case _ => true
      }
    }

    cached.foreach(handleCachedResource)

    nonCached
      .groupBy(_.ahcRequest.getUri.getHost)
      .foreach {
        case (host, res) =>
          val availableTokens = availableTokensByHost(host)
          val (immediate, buffered) = res.splitAt(availableTokens)
          fetchResources(host, immediate)
          bufferResources(host, buffered)
      }
  }

  private def done(): Unit = {
    logger.debug("All resources were fetched")
    // FIXME only do so if not silent
    primaryTx.next ! session.logGroupAsyncRequests(nowMillis - start, okCount, koCount)
    context.stop(self)
  }

  private def resourceFetched(uri: Uri, status: Status, silent: Boolean): Unit = {

      def releaseToken(host: String): Unit = {

          @tailrec
          def releaseTokenRec(bufferedResourcesForHost: List[HttpRequest]): Unit =
            bufferedResourcesForHost match {
              case Nil =>
                // nothing to send for this host for now
                availableTokensByHost += host -> (availableTokensByHost(host) + 1)

              case request :: tail =>
                bufferedResourcesByHost += host -> tail
                val requestUri = request.ahcRequest.getUri
                CacheHandling.getExpire(protocol, session, requestUri) match {
                  case None =>
                    // recycle token, fetch a buffered resource
                    fetchResource(request)

                  case Some(expire) if nowMillis > expire =>
                    // expire reached
                    session = CacheHandling.clearExpire(session, requestUri)
                    fetchResource(request)

                  case _ =>
                    handleCachedResource(request)
                    releaseTokenRec(tail)
                }
            }

        val hostBufferedResources = bufferedResourcesByHost.get(uri.getHost) match {
          case None            => Nil
          case Some(resources) => resources
        }

        releaseTokenRec(hostBufferedResources)
      }

    logger.debug(s"Resource $uri was fetched")
    pendingResourcesCount -= 1

    if (!silent) {
      if (status == OK)
        okCount = okCount + 1
      else
        koCount = koCount + 1
    }

    if (pendingResourcesCount == 0)
      done()
    else
      releaseToken(uri.getHost)
  }

  private def cssFetched(uri: Uri, status: Status, statusCode: Option[Int], lastModifiedOrEtag: Option[String], content: String): Unit = {

      def parseCssResources(): List[HttpRequest] = {
        val inferred = CssContentCache.cache.getOrElseUpdate(uri, CssParser.extractResources(uri, content))
        val filtered = applyResourceFilters(inferred, filters)
        resourcesToRequests(filtered, session, protocol, throttled)
      }

    if (status == OK) {
      // this css might contain some resources

      val cssResources: List[HttpRequest] =
        statusCode match {
          case Some(200) =>
            lastModifiedOrEtag match {
              case Some(newLastModifiedOrEtag) =>
                // resource can be cached, try to get from cache instead of parsing again

                val cacheKey = InferredResourcesCacheKey(protocol, uri)

                InferredResourcesCache.cache.get(cacheKey) match {
                  case Some(InferredPageResources(`newLastModifiedOrEtag`, inferredResources)) =>
                    //cache entry didn't expire, use it
                    inferredResources

                  case _ =>
                    // cache entry missing or expired, set/update it
                    CssContentCache.cache.remove(uri)
                    val inferredResources = parseCssResources()
                    InferredResourcesCache.cache.put(InferredResourcesCacheKey(protocol, uri), InferredPageResources(newLastModifiedOrEtag, inferredResources))
                    inferredResources
                }

              case None =>
                // don't cache
                parseCssResources()
            }

          case Some(304) =>
            // resource was already cached
            InferredResourcesCache.cache.get(InferredResourcesCacheKey(protocol, uri)) match {
              case Some(inferredPageResources) => inferredPageResources.requests
              case _ =>
                logger.warn(s"Got a 304 for $uri but could find cache entry?!")
                Nil
            }
          case _ => Nil
        }

      val filtered = cssResources.filterNot(resource => alreadySeen.contains(resource.ahcRequest.getUri))
      fetchOrBufferResources(filtered)
    }
  }

  def receive: Receive = {
    case RegularResourceFetched(uri, status, sessionUpdates, silent) =>
      session = sessionUpdates(session)
      resourceFetched(uri, status, silent)

    case CssResourceFetched(uri, status, sessionUpdates, silent, statusCode, lastModifiedOrEtag, content) =>
      session = sessionUpdates(session)
      cssFetched(uri, status, statusCode, lastModifiedOrEtag, content)
      resourceFetched(uri, status, silent)
  }
}
