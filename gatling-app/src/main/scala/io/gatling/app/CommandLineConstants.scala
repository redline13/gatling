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
package io.gatling.app

import scopt.{ Read, OptionDef, OptionParser }

case class CommandLineConstant(full: String, abbr: String)

object CommandLineConstants {

  trait CommandLineConstantsSupport[C] { self: OptionParser[C] =>

    def help(constant: CommandLineConstant): OptionDef[Unit, C] = help(constant.full).abbr(constant.abbr)
    def opt[A: Read](constant: CommandLineConstant): OptionDef[A, C] = opt[A](constant.full).abbr(constant.abbr)
  }

  val Help = CommandLineConstant("help", "h")
  val NoReports = CommandLineConstant("no-reports", "nr")
  val ReportsOnly = CommandLineConstant("reports-only", "ro")
  val DataFolder = CommandLineConstant("data-folder", "df")
  val ResultsFolder = CommandLineConstant("results-folder", "rf")
  val RequestBodiesFolder = CommandLineConstant("request-bodies-folder", "rbf")
  val SimulationsFolder = CommandLineConstant("simulations-folder", "sf")
  val SimulationsBinariesFolder = CommandLineConstant("binaries-folder", "bf")
  val Simulation = CommandLineConstant("simulation", "s")
  val OutputDirectoryBaseName = CommandLineConstant("output-name", "on")
  val SimulationDescription = CommandLineConstant("run-description", "rd")
  val Mute = CommandLineConstant("mute", "m")
  var Singular = CommandLineConstant("singular", "singular")
}
