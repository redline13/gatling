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
package io.gatling.http.response

import java.security.MessageDigest

import com.ning.http.client.providers.netty.request.NettyRequest
import io.gatling.http.util.HttpHelper

import scala.collection.mutable.ArrayBuffer
import scala.math.max

import org.jboss.netty.buffer.ChannelBuffer

import com.ning.http.client.{ FluentCaseInsensitiveStringsMap, HttpResponseBodyPart, HttpResponseHeaders, HttpResponseStatus, Request }
import com.ning.http.client.providers.netty.response.NettyResponseBodyPart
import com.typesafe.scalalogging.StrictLogging

import io.gatling.core.config.GatlingConfiguration
import io.gatling.core.util.StringHelper.bytes2Hex
import io.gatling.core.util.TimeHelper.nowMillis
import io.gatling.http.HeaderNames
import io.gatling.http.check.HttpCheck
import io.gatling.http.check.checksum.ChecksumCheck
import io.gatling.http.util.HttpHelper.{ isCss, isHtml, isTxt }

object ResponseBuilder extends StrictLogging {

  val EmptyHeaders = new FluentCaseInsensitiveStringsMap

  val Identity: Response => Response = identity[Response]

  private val IsDebugEnabled = logger.underlying.isDebugEnabled

  def newResponseBuilderFactory(checks: List[HttpCheck],
                                responseTransformer: Option[PartialFunction[Response, Response]],
                                discardResponseChunks: Boolean,
                                inferHtmlResources: Boolean): Request => ResponseBuilder = {

    val checksumChecks = checks.collect {
      case checksumCheck: ChecksumCheck => checksumCheck
    }

    val responseBodyUsageStrategies = checks.flatMap(_.responseBodyUsageStrategy).toSet

    val storeBodyParts = IsDebugEnabled || !discardResponseChunks || responseBodyUsageStrategies.nonEmpty || responseTransformer.isDefined

    request: Request => new ResponseBuilder(request, checksumChecks, responseBodyUsageStrategies, responseTransformer, storeBodyParts, inferHtmlResources)
  }
}

class ResponseBuilder(request: Request,
                      checksumChecks: List[ChecksumCheck],
                      bodyUsageStrategies: Set[ResponseBodyUsageStrategy],
                      responseProcessor: Option[PartialFunction[Response, Response]],
                      storeBodyParts: Boolean,
                      inferHtmlResources: Boolean) {

  val computeChecksums = checksumChecks.nonEmpty
  var storeHtmlOrCss = false
  var firstByteSent = nowMillis
  var lastByteSent = 0L
  var firstByteReceived = 0L
  var lastByteReceived = 0L
  private var status: Option[HttpResponseStatus] = None
  private var headers: FluentCaseInsensitiveStringsMap = ResponseBuilder.EmptyHeaders
  private val chunks = new ArrayBuffer[ChannelBuffer]
  private var digests: Map[String, MessageDigest] = initDigests()
  private var nettyRequest: Option[NettyRequest] = None

  def initDigests(): Map[String, MessageDigest] =
    if (computeChecksums)
      checksumChecks.foldLeft(Map.empty[String, MessageDigest]) { (map, check) =>
        map + (check.algorithm -> MessageDigest.getInstance(check.algorithm))
      }
    else
      Map.empty[String, MessageDigest]

  def updateFirstByteSent(): Unit = firstByteSent = nowMillis

  def setNettyRequest(nettyRequest: NettyRequest) = {
    this.nettyRequest = Some(nettyRequest)
  }

  def reset(): Unit = {
    firstByteSent = nowMillis
    lastByteSent = 0L
    firstByteReceived = 0L
    lastByteReceived = 0L
    status = None
    headers = ResponseBuilder.EmptyHeaders
    chunks.clear()
    digests = initDigests()
  }

  def updateLastByteSent(): Unit = lastByteSent = nowMillis

  def updateLastByteReceived(): Unit = lastByteReceived = nowMillis

  def accumulate(status: HttpResponseStatus): Unit = {
    this.status = Some(status)
    val now = nowMillis
    firstByteReceived = now
    lastByteReceived = now
  }

  def accumulate(headers: HttpResponseHeaders): Unit = {
    this.headers = headers.getHeaders
    storeHtmlOrCss = inferHtmlResources && (isHtml(headers.getHeaders) || isCss(headers.getHeaders))
    updateLastByteReceived()
  }

  def accumulate(bodyPart: HttpResponseBodyPart): Unit = {

    updateLastByteReceived()

    val channelBuffer = bodyPart.asInstanceOf[NettyResponseBodyPart].getChannelBuffer

    if (storeBodyParts || storeHtmlOrCss)
      chunks += channelBuffer

    if (computeChecksums)
      digests.values.foreach(_.update(bodyPart.getBodyByteBuffer))
  }

  def build(implicit configuration: GatlingConfiguration): Response = {

    // time measurement is imprecise due to multi-core nature
    // moreover, ProgressListener might be called AFTER ChannelHandler methods 
    // ensure request doesn't end before starting
    lastByteSent = max(lastByteSent, firstByteSent)
    // ensure response doesn't start before request ends
    firstByteReceived = max(firstByteReceived, lastByteSent)
    // ensure response doesn't end before starting
    lastByteReceived = max(lastByteReceived, firstByteReceived)

    val checksums = digests.foldLeft(Map.empty[String, String]) { (map, entry) =>
      val (algo, md) = entry
      map + (algo -> bytes2Hex(md.digest))
    }

    val bodyLength = chunks.foldLeft(0) { (sum, chunk) =>
      sum + chunk.readableBytes
    }

    val bodyUsages = bodyUsageStrategies.map(_.bodyUsage(bodyLength))

    val charset = Option(headers.getFirstValue(HeaderNames.ContentType))
      .flatMap(HttpHelper.extractCharsetFromContentType)
      .getOrElse(configuration.core.charset)

    val body: ResponseBody =
      if (chunks.isEmpty)
        NoResponseBody

      else if (bodyUsages.contains(ByteArrayResponseBodyUsage))
        ByteArrayResponseBody(chunks, charset)

      else if (bodyUsages.contains(InputStreamResponseBodyUsage) || bodyUsages.isEmpty)
        InputStreamResponseBody(chunks, charset)

      else if (isTxt(headers))
        StringResponseBody(chunks, charset)

      else
        ByteArrayResponseBody(chunks, charset)

    val rawResponse = HttpResponse(request, nettyRequest, status, headers, body, checksums, bodyLength, charset, firstByteSent, lastByteSent, firstByteReceived, lastByteReceived)

    responseProcessor match {
      case None            => rawResponse
      case Some(processor) => processor.applyOrElse(rawResponse, ResponseBuilder.Identity)
    }
  }
}
