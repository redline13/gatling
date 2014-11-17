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
package io.gatling.recorder.config

object ConfigKeys {

  val ConfigRoot = "recorder"

  object core {
    val Encoding = "recorder.core.encoding"
    val SimulationOutputFolder = "recorder.core.outputFolder"
    val BodiesFolder = "recorder.core.bodiesFolder"
    val Package = "recorder.core.package"
    val ClassName = "recorder.core.className"
    val ThresholdForPauseCreation = "recorder.core.thresholdForPauseCreation"
    val SaveConfig = "recorder.core.saveConfig"
  }
  object filters {
    val FilterStrategy = "recorder.filters.filterStrategy"
    val WhitelistPatterns = "recorder.filters.whitelist"
    val BlacklistPatterns = "recorder.filters.blacklist"
  }
  object http {
    val AutomaticReferer = "recorder.http.automaticReferer"
    val FollowRedirect = "recorder.http.followRedirect"
    val InferHtmlResources = "recorder.http.inferHtmlResources"
    val RemoveConditionalCache = "recorder.http.removeConditionalCache"
    val CheckResponseBodies = "recorder.http.checkResponseBodies"
  }
  object proxy {
    val Port = "recorder.proxy.port"

    object https {
      val Mode = "recorder.proxy.https.mode"

      object keyStore {
        val Path = "recorder.proxy.https.keyStore.path"
        val Password = "recorder.proxy.https.keyStore.password"
        val Type = "recorder.proxy.https.keyStore.type"
      }

      object customCertificate {
        val CertificatePath = "recorder.proxy.https.customCertificate.certificatePath"
        val PrivateKeyPath = "recorder.proxy.https.customCertificate.privateKeyPath"
      }
    }

    object outgoing {
      val Host = "recorder.proxy.outgoing.host"
      val Username = "recorder.proxy.outgoing.username"
      val Password = "recorder.proxy.outgoing.password"
      val Port = "recorder.proxy.outgoing.port"
      val SslPort = "recorder.proxy.outgoing.sslPort"
    }
  }
  object netty {
    val MaxInitialLineLength = "recorder.netty.maxInitialLineLength"
    val MaxHeaderSize = "recorder.netty.maxHeaderSize"
    val MaxChunkSize = "recorder.netty.maxChunkSize"
    val MaxContentLength = "recorder.netty.maxContentLength"
  }
}
