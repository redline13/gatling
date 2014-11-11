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
package io.gatling.core.check.extractor.regex

import org.scalatest.{ FlatSpec, Matchers }

import io.gatling.core.config.GatlingConfiguration
import io.gatling.core.test.ValidationValues

class RegexExtractorSpec extends FlatSpec with Matchers with ValidationValues {

  implicit val config = GatlingConfiguration.setUpForTestPure()
  RegexExtractor.PatternCache.initialize(_.core.extract.regex.cacheMaxCapacity)

  "count" should "return Some(0) when no results" in {
    val stringRegexExtractor = new CountRegexExtractor("""foo""")
    stringRegexExtractor("""{"id":"1072920417","result":"[{\"SearchDefinitionID\":116},{\"SearchDefinitionID\":108}]","error":null}""").succeeded shouldBe Some(0)
  }

  "extractMultiple" should "return expected result with anywhere expression" in {
    val stringRegexExtractor = new MultipleRegexExtractor[String](""""SearchDefinitionID\\":(\d*)""")
    stringRegexExtractor("""{"id":"1072920417","result":"[{\"SearchDefinitionID\":116},{\"SearchDefinitionID\":108}]","error":null}""").succeeded shouldBe Some(List("116", "108"))
  }
}
