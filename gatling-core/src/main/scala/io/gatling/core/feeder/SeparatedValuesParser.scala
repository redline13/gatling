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

import scala.collection.breakOut
import scala.io.Source

import au.com.bytecode.opencsv.CSVParser
import io.gatling.core.config.GatlingConfiguration
import io.gatling.core.config.Resource
import io.gatling.core.util.IO._

object SeparatedValuesParser {

  val CommaSeparator = ','
  val SemicolonSeparator = ';'
  val TabulationSeparator = '\t'

  def parse(resource: Resource, separator: Char, doubleQuote: Char, rawSplit: Boolean)(implicit configuration: GatlingConfiguration): IndexedSeq[Record[String]] =
    withSource(Source.fromInputStream(resource.inputStream)(configuration.core.codec)) { source =>
      stream(source, separator, doubleQuote, rawSplit).toVector
    }

  def stream(source: Source, separator: Char, doubleQuote: Char, rawSplit: Boolean): Iterator[Record[String]] = {
    val parseLine: String => Array[String] =
      if (rawSplit) {
        val separatorString = separator.toString
        _.split(separatorString)
      } else {
        val csvParser = new CSVParser(separator, doubleQuote)
        csvParser.parseLine
      }

    val rawLines = source.getLines().map(parseLine)
    val headers =
      try
        rawLines.next().map(_.trim)
      catch {
        case e: NoSuchElementException =>
          throw new IllegalArgumentException("SeparatedValuesParser expects files to contain a first headers line")
      }
    rawLines.map(headers.zip(_)(breakOut))
  }
}
