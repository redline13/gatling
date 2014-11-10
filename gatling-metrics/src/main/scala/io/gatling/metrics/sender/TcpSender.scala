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

import java.net.Socket

import io.gatling.core.akka.AkkaDefaults
import io.gatling.core.config.GatlingConfiguration
import io.gatling.core.util.FastBufferedOutputStream

class TcpSender(implicit configuration: GatlingConfiguration) extends MetricsSender with AkkaDefaults {

  val os = {
    val sos = new Socket(configuration.data.graphite.host, configuration.data.graphite.port).getOutputStream
    system.registerOnTermination(sos.close())
    new FastBufferedOutputStream(sos, configuration.data.graphite.bufferSize)
  }

  def sendToGraphite(bytes: Array[Byte]): Unit = os.write(bytes)

  def flush(): Unit = os.flush()
}
