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
package io.gatling.http.request

import io.gatling.core.config.GatlingConfiguration
import io.gatling.core.config.Resource
import io.gatling.core.session.Expression
import io.gatling.core.session.el.EL
import io.gatling.core.util.IO._
import io.gatling.core.util.cache._
import io.gatling.core.validation.Validation

object ELFileBodies {

  val ELFileBodyCache = new ThreadSafeCache[String, Validation[Expression[String]]]("ELFileBodyCache")
  //val ELFileBodyCacheEnabled = configuration.http.elFileBodiesCacheMaxCapacity > 0
  //val ELFileBodyCache = ThreadSafeCache[String, Validation[Expression[String]]](configuration.http.elFileBodiesCacheMaxCapacity)

  def asString(filePath: Expression[String])(implicit configuration: GatlingConfiguration): Expression[String] = {

      def compileFile(path: String): Validation[Expression[String]] =
        Resource.requestBody(path)
          .map(resource => withCloseable(resource.inputStream) {
            _.toString(configuration.core.charset)
          }).map(_.el[String])

      def pathToExpression(path: String) =
        if (ELFileBodyCache.enabled) ELFileBodyCache.getOrElsePutIfAbsent(path, compileFile(path))
        else compileFile(path)

    session =>
      for {
        path <- filePath(session)
        expression <- pathToExpression(path)
        body <- expression(session)
      } yield body
  }
}
