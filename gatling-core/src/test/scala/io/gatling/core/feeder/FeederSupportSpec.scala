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
package io.gatling.core.feeder

import io.gatling.core.json.Jackson
import org.scalatest.{ FlatSpec, Matchers }

import io.gatling.core.config.GatlingConfiguration

class FeederSupportSpec extends FlatSpec with Matchers with FeederSupport {

  implicit val config = GatlingConfiguration.setUpForTest()
  Jackson.initialize

  "tsv" should "handle file without escape char" in {
    val data = tsv("sample1.tsv").build.toArray

    data shouldBe Array(Map("foo" -> "hello", "bar" -> "world"))
  }

  it should "handle file with escape char" in {
    val data = tsv("sample2.tsv").build.toArray

    data shouldBe Array(Map("foo" -> "hello", "bar" -> "world"))
  }

  "jsonFile" should "handle proper JSON file" in {

    val data = jsonFile("test.json").build.toArray

    data.size shouldBe 2
    data(0)("id") shouldBe 19434
  }
}
