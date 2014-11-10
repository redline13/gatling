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
package io.gatling.metrics.sender

import java.nio.charset.StandardCharsets.UTF_8

import io.gatling.core.config.GatlingConfiguration

object MetricsSender {

  def newMetricsSender(implicit configuration: GatlingConfiguration): MetricsSender = configuration.data.graphite.protocol.toLowerCase match {
    case "tcp" => new TcpSender
    case "udp" => new UdpSender
    case p @ _ => throw new RuntimeException(s"The protocol '$p' specified in the configuration is not supported")
  }
}

abstract class MetricsSender {

  def sendToGraphite[T: Numeric](metricPath: String, value: T, epoch: Long): Unit = {
    val msg = s"$metricPath $value $epoch\n"
    val bytes = msg.getBytes(UTF_8)
    sendToGraphite(bytes)
  }

  def sendToGraphite(bytes: Array[Byte]): Unit

  def flush(): Unit
}
