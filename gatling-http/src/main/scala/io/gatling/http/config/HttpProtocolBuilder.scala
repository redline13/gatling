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
package io.gatling.http.config

import java.net.InetAddress

import com.ning.http.client.{ RequestBuilderBase, Request, SignatureCalculator, Realm }
import com.typesafe.scalalogging.StrictLogging

import io.gatling.core.config.GatlingConfiguration
import io.gatling.core.filter.{ BlackList, Filters, WhiteList }
import io.gatling.core.session._
import io.gatling.core.session.el.EL
import io.gatling.http.HeaderNames._
import io.gatling.http.ahc.ProxyConverter
import io.gatling.http.check.HttpCheck
import io.gatling.http.request.ExtraInfoExtractor
import io.gatling.http.response.Response
import io.gatling.http.util.HttpHelper

/**
 * HttpProtocolBuilder class companion
 */
object HttpProtocolBuilder {

  def DefaultHttpProtocolBuilder(implicit config: GatlingConfiguration) = new HttpProtocolBuilder(HttpProtocol.DefaultHttpProtocol)

  implicit def toHttpProtocol(builder: HttpProtocolBuilder): HttpProtocol = builder.build
}

/**
 * Builder for HttpProtocol used in DSL
 *
 * @param protocol the protocol being built
 */
case class HttpProtocolBuilder(protocol: HttpProtocol) extends StrictLogging {

  def baseURL(url: String) = copy(protocol = protocol.copy(baseURLs = List(url)))
  def baseURLs(urls: String*): HttpProtocolBuilder = baseURLs(urls.toList)
  def baseURLs(urls: List[String]): HttpProtocolBuilder = copy(protocol = protocol.copy(baseURLs = urls))
  def warmUp(url: String): HttpProtocolBuilder = copy(protocol = copy(protocol.copy(warmUpUrl = Some(url))))
  def disableWarmUp: HttpProtocolBuilder = copy(protocol = protocol.copy(warmUpUrl = None))

  // enginePart
  private def newEnginePart(enginePart: HttpProtocolEnginePart) = copy(protocol = copy(protocol.copy(enginePart = enginePart)))
  def disableClientSharing = newEnginePart(protocol.enginePart.copy(shareClient = false))
  def shareConnections = newEnginePart(protocol.enginePart.copy(shareConnections = true))
  def virtualHost(virtualHost: Expression[String]) = newEnginePart(protocol.enginePart.copy(virtualHost = Some(virtualHost)))
  def localAddress(localAddress: InetAddress) = newEnginePart(protocol.enginePart.copy(localAddress = Some(localAddress)))
  def maxConnectionsPerHostLikeFirefoxOld = maxConnectionsPerHost(2)
  def maxConnectionsPerHostLikeFirefox = maxConnectionsPerHost(6)
  def maxConnectionsPerHostLikeOperaOld = maxConnectionsPerHost(4)
  def maxConnectionsPerHostLikeOpera = maxConnectionsPerHost(6)
  def maxConnectionsPerHostLikeSafariOld = maxConnectionsPerHost(4)
  def maxConnectionsPerHostLikeSafari = maxConnectionsPerHost(6)
  def maxConnectionsPerHostLikeIE7 = maxConnectionsPerHost(2)
  def maxConnectionsPerHostLikeIE8 = maxConnectionsPerHost(6)
  def maxConnectionsPerHostLikeIE10 = maxConnectionsPerHost(8)
  def maxConnectionsPerHostLikeChrome = maxConnectionsPerHost(6)
  def maxConnectionsPerHost(max: Int): HttpProtocolBuilder = newEnginePart(protocol.enginePart.copy(maxConnectionsPerHost = max))

  // requestPart
  private def newRequestPart(requestPart: HttpProtocolRequestPart) = copy(protocol = copy(protocol.copy(requestPart = requestPart)))
  def disableAutoReferer = newRequestPart(protocol.requestPart.copy(autoReferer = false))
  def disableCaching = newRequestPart(protocol.requestPart.copy(cache = false))
  def header(name: String, value: Expression[String]) = newRequestPart(protocol.requestPart.copy(baseHeaders = protocol.requestPart.baseHeaders + (name -> value)))
  @deprecated("Use headers instead", "2.0.0-RC6")
  def baseHeaders(h: Map[String, String]) = headers(h)
  def headers(headers: Map[String, String]) = newRequestPart(protocol.requestPart.copy(baseHeaders = protocol.requestPart.baseHeaders ++ headers.mapValues(_.el[String])))
  def acceptHeader(value: Expression[String]) = newRequestPart(protocol.requestPart.copy(baseHeaders = protocol.requestPart.baseHeaders + (Accept -> value)))
  def acceptCharsetHeader(value: Expression[String]) = newRequestPart(protocol.requestPart.copy(baseHeaders = protocol.requestPart.baseHeaders + (AcceptCharset -> value)))
  def acceptEncodingHeader(value: Expression[String]) = newRequestPart(protocol.requestPart.copy(baseHeaders = protocol.requestPart.baseHeaders + (AcceptEncoding -> value)))
  def acceptLanguageHeader(value: Expression[String]) = newRequestPart(protocol.requestPart.copy(baseHeaders = protocol.requestPart.baseHeaders + (AcceptLanguage -> value)))
  def authorizationHeader(value: Expression[String]) = newRequestPart(protocol.requestPart.copy(baseHeaders = protocol.requestPart.baseHeaders + (Authorization -> value)))
  def connection(value: Expression[String]) = newRequestPart(protocol.requestPart.copy(baseHeaders = protocol.requestPart.baseHeaders + (Connection -> value)))
  def contentTypeHeader(value: Expression[String]) = newRequestPart(protocol.requestPart.copy(baseHeaders = protocol.requestPart.baseHeaders + (ContentType -> value)))
  def doNotTrackHeader(value: Expression[String]) = newRequestPart(protocol.requestPart.copy(baseHeaders = protocol.requestPart.baseHeaders + (DNT -> value)))
  def userAgentHeader(value: Expression[String]) = newRequestPart(protocol.requestPart.copy(baseHeaders = protocol.requestPart.baseHeaders + (UserAgent -> value)))
  def basicAuth(username: Expression[String], password: Expression[String]) = authRealm(HttpHelper.buildBasicAuthRealm(username, password))
  def digestAuth(username: Expression[String], password: Expression[String]) = authRealm(HttpHelper.buildDigestAuthRealm(username, password))
  def ntlmAuth(username: Expression[String], password: Expression[String], ntlmDomain: Expression[String], ntlmHost: Expression[String]) = authRealm(HttpHelper.buildNTLMAuthRealm(username, password, ntlmDomain, ntlmHost))
  def authRealm(realm: Expression[Realm]) = newRequestPart(protocol.requestPart.copy(realm = Some(realm)))
  def silentResources = newRequestPart(protocol.requestPart.copy(silentResources = true))
  def silentURI(regex: String) = newRequestPart(protocol.requestPart.copy(silentURI = Some(regex.r.pattern)))
  def disableUrlEscaping = newRequestPart(protocol.requestPart.copy(disableUrlEscaping = true))
  def signatureCalculator(calculator: Expression[SignatureCalculator]): HttpProtocolBuilder = newRequestPart(protocol.requestPart.copy(signatureCalculator = Some(calculator)))
  def signatureCalculator(calculator: SignatureCalculator): HttpProtocolBuilder = signatureCalculator(calculator.expression)
  def signatureCalculator(calculator: (Request, RequestBuilderBase[_]) => Unit): HttpProtocolBuilder = signatureCalculator(new SignatureCalculator {
    def calculateAndAddSignature(request: Request, requestBuilder: RequestBuilderBase[_]): Unit = calculator(request, requestBuilder)
  })

  // responsePart
  private def newResponsePart(responsePart: HttpProtocolResponsePart) = copy(protocol = copy(protocol.copy(responsePart = responsePart)))
  def disableFollowRedirect = newResponsePart(protocol.responsePart.copy(followRedirect = false))
  def maxRedirects(max: Int) = newResponsePart(protocol.responsePart.copy(maxRedirects = Some(max)))
  def disableResponseChunksDiscarding = newResponsePart(protocol.responsePart.copy(discardResponseChunks = false))
  def extraInfoExtractor(f: ExtraInfoExtractor) = newResponsePart(protocol.responsePart.copy(extraInfoExtractor = Some(f)))
  def transformResponse(responseTransformer: PartialFunction[Response, Response]) = newResponsePart(protocol.responsePart.copy(responseTransformer = Some(responseTransformer)))
  def check(checks: HttpCheck*) = newResponsePart(protocol.responsePart.copy(checks = protocol.responsePart.checks ::: checks.toList))
  def inferHtmlResources(): HttpProtocolBuilder = inferHtmlResources(None)
  def inferHtmlResources(white: WhiteList): HttpProtocolBuilder = inferHtmlResources(Some(Filters(white, BlackList())))
  def inferHtmlResources(white: WhiteList, black: BlackList): HttpProtocolBuilder = inferHtmlResources(Some(Filters(white, black)))
  def inferHtmlResources(black: BlackList, white: WhiteList = WhiteList(Nil)): HttpProtocolBuilder = inferHtmlResources(Some(Filters(black, white)))
  private def inferHtmlResources(filters: Option[Filters]) = newResponsePart(protocol.responsePart.copy(inferHtmlResources = true, htmlResourcesInferringFilters = filters))

  // wsPart
  private def newWsPart(wsPart: HttpProtocolWsPart) = copy(protocol = copy(protocol.copy(wsPart = wsPart)))
  def wsBaseURL(url: String) = newWsPart(protocol.wsPart.copy(wsBaseURLs = List(url)))
  def wsBaseURLs(urls: String*) = newWsPart(protocol.wsPart.copy(wsBaseURLs = urls.toList))
  def wsBaseURLs(urls: List[String]) = newWsPart(protocol.wsPart.copy(wsBaseURLs = urls))
  def wsReconnect = newWsPart(protocol.wsPart.copy(reconnect = true))
  def wsMaxReconnects(max: Int) = newWsPart(protocol.wsPart.copy(maxReconnects = Some(max)))

  // proxyPart
  private def newProxyPart(proxyPart: HttpProtocolProxyPart) = copy(protocol = copy(protocol.copy(proxyPart = proxyPart)))
  def noProxyFor(hosts: String*): HttpProtocolBuilder = newProxyPart(protocol.proxyPart.copy(proxyExceptions = hosts))
  def proxy(httpProxy: Proxy): HttpProtocolBuilder = newProxyPart(protocol.proxyPart.copy(proxies = Some(httpProxy.proxyServers)))

  def build = {
    require(protocol.enginePart.shareClient || !protocol.enginePart.shareConnections, "Invalid protocol configuration: if you stop sharing the HTTP client, you can't share connections!")
    protocol
  }
}
