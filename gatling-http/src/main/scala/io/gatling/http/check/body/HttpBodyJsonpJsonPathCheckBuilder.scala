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
package io.gatling.http.check.body

import com.typesafe.scalalogging.StrictLogging

import io.gatling.core.check.{ DefaultMultipleFindCheckBuilder, Preparer }
import io.gatling.core.check.extractor.jsonpath.{ CountJsonPathExtractor, JsonFilter, MultipleJsonPathExtractor, SingleJsonPathExtractor }
import io.gatling.core.config.GatlingConfiguration
import io.gatling.core.json.{ Jackson, Boon }
import io.gatling.core.session.{ Expression, RichExpression }
import io.gatling.core.validation.{ Validation, FailureWrapper, SuccessWrapper }
import io.gatling.http.check.HttpCheck
import io.gatling.http.check.HttpCheckBuilders._
import io.gatling.http.response.Response

trait HttpBodyJsonpJsonPathOfType {
  self: HttpBodyJsonpJsonPathCheckBuilder[String] =>

  def ofType[X: JsonFilter] = new HttpBodyJsonpJsonPathCheckBuilder[X](path)
}

object HttpBodyJsonpJsonPathCheckBuilder extends StrictLogging {

  val JsonpRegex = """^\w+(?:\[\"\w+\"\]|\.\w+)*\((.*)\);?\s*$""".r

  def JsonParser(implicit configuration: GatlingConfiguration) =
    if (configuration.core.extract.jsonPath.preferJackson) Jackson
    else Boon

  def parseJsonpString(string: String): Validation[Any] = string match {
    case JsonpRegex(jsonp) =>
      try {
        JsonParser.parse(jsonp).success
      } catch {
        case e: Exception =>
          val message = s"Could not parse JSONP string into a JSON object: ${e.getMessage}"
          logger.info(message, e)
          message.failure
      }
    case _ =>
      val message = "Regex could not extract JSON object from JSONP response"
      logger.info(message)
      message.failure
  }

  val JsonpPreparer: Preparer[Response, Any] = response => parseJsonpString(response.body.string)

  def jsonpJsonPath(path: Expression[String]) = new HttpBodyJsonpJsonPathCheckBuilder[String](path) with HttpBodyJsonpJsonPathOfType
}

class HttpBodyJsonpJsonPathCheckBuilder[X: JsonFilter](private[body] val path: Expression[String])
    extends DefaultMultipleFindCheckBuilder[HttpCheck, Response, Any, X](StringBodyExtender,
      HttpBodyJsonpJsonPathCheckBuilder.JsonpPreparer) {

  def findExtractor(occurrence: Int) = path.map(new SingleJsonPathExtractor(_, occurrence))
  def findAllExtractor = path.map(new MultipleJsonPathExtractor(_))
  def countExtractor = path.map(new CountJsonPathExtractor(_))
}
