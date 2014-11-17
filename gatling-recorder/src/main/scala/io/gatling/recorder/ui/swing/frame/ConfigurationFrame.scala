/**
 * Copyright 2011-2014 eBusiness Information, Groupe Excilys (www.ebusinessinformation.fr)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *                 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gatling.recorder.ui.swing.frame

import java.awt.Font
import javax.swing.filechooser.FileNameExtensionFilter

import scala.collection.JavaConversions.seqAsJavaList
import scala.swing._
import scala.swing.BorderPanel.Position._
import scala.swing.FileChooser.SelectionMode
import scala.swing.ListView.Renderer
import scala.swing.event.{ ButtonClicked, KeyReleased, SelectionChanged }
import scala.util.Try

import io.gatling.core.util.PathHelper._
import io.gatling.core.util.StringHelper.RichString
import io.gatling.core.util.IO._
import io.gatling.recorder._
import io.gatling.recorder.config._
import io.gatling.recorder.config.FilterStrategy.BlacklistFirst
import io.gatling.recorder.http._
import io.gatling.recorder.http.ssl.SslServerContextFactory.GatlingCAFactory
import io.gatling.recorder.ui.RecorderFrontend
import io.gatling.recorder.ui.swing.Commons._
import io.gatling.recorder.ui.swing.component.FilterTable
import io.gatling.recorder.ui.swing.frame.ValidationHelper._
import io.gatling.recorder.ui.swing.util.CharsetHelper
import io.gatling.recorder.ui.swing.util.UIHelper._

class ConfigurationFrame(frontend: RecorderFrontend)(implicit configuration: RecorderConfiguration) extends MainFrame {

  /************************************/
  /**           COMPONENTS           **/
  /************************************/

  /* Top panel components */
  private val modeSelector = new ComboBox[RecorderMode](Seq(Proxy, Har)) {
    selection.index = 0
    renderer = Renderer(_.name)
  }

  /* Network panel components */
  private val localProxyHttpPort = new TextField(4)
  private val httpsModes = new ComboBox[HttpsMode](HttpsMode.AllHttpsModes) {
    selection.index = 0
    renderer = Renderer(_.name)
  }
  private val certificateDownloadPath = new FileChooser { fileSelectionMode = SelectionMode.FilesOnly }
  private val downloadCertificate = new Button(Action("Download Gatling's CA")(certificateDownloadPath.saveSelection().foreach(downloadGatlingCertificate))) { visible = false }
  private val outgoingProxyHost = new TextField(12)
  private val outgoingProxyHttpPort = new TextField(4) { enabled = false }
  private val outgoingProxyHttpsPort = new TextField(4) { enabled = false }
  private val outgoingProxyUsername = new TextField(10) { enabled = false }
  private val outgoingProxyPassword = new TextField(10) { enabled = false }

  /* Har Panel components */
  private val harPath = new TextField(66)
  private val harFileFilter = new FileNameExtensionFilter("HTTP Archive (.har)", "har")
  private val harFileChooser = new FileChooser { fileSelectionMode = SelectionMode.FilesOnly; fileFilter = harFileFilter }
  private val harFileBrowserButton = Button("Browse")(harFileChooser.openSelection().foreach(harPath.text = _))

  /* Simulation panel components */
  private val simulationPackage = new TextField(30)
  private val simulationClassName = new TextField(30)
  private val followRedirects = new CheckBox("Follow Redirects?")
  private val inferHtmlResources = new CheckBox("Infer html resources?")
  private val removeConditionalCache = new CheckBox("Remove conditional cache headers?")
  private val checkResponseBodies = new CheckBox("Save & check response bodies?")
  private val automaticReferers = new CheckBox("Automatic Referers?")

  /* Output panel components */
  private val outputEncoding = new ComboBox[String](CharsetHelper.orderedLabelList)
  private val outputFolderPath = new TextField(66)
  private val outputFolderChooser = new FileChooser { fileSelectionMode = SelectionMode.DirectoriesOnly }
  private val outputFolderBrowserButton = Button("Browse")(outputFolderChooser.saveSelection().foreach(outputFolderPath.text = _))

  /* Filters panel components */
  private val whiteListTable = new FilterTable("Whitelist")
  private val addWhiteListFilter = Button("+")(whiteListTable.addRow())
  private val removeWhiteListFilter = Button("-")(whiteListTable.removeSelectedRow())
  private val clearWhiteListFilters = Button("Clear")(whiteListTable.removeAllElements())

  private val blackListTable = new FilterTable("Blacklist")
  private val addBlackListFilter = Button("+")(blackListTable.addRow())
  private val removeBlackListFilter = Button("-")(blackListTable.removeSelectedRow())
  private val clearBlackListFilters = Button("Clear")(blackListTable.removeAllElements())
  private val ruleOutStaticResources = Button("No static resources")(blackListStaticResources())

  private val filterStrategies = new ComboBox[FilterStrategy](FilterStrategy.AllStrategies) {
    selection.index = 0
    renderer = Renderer(_.name)
  }

  /* Bottom panel components */
  private val savePreferences = new CheckBox("Save preferences") { horizontalTextPosition = Alignment.Left }
  private val start = Button("Start !")(reloadConfigurationAndStart())

  registerValidators()
  populateItemsFromConfiguration()

  /**********************************/
  /**           UI SETUP           **/
  /**********************************/

  /* Frame setup */
  title = "Gatling Recorder - Configuration"
  resizable = true
  peer.setIconImages(IconList)

  /* Layout setup */
  val root = new BorderPanel {
    /* Top panel: Gatling logo & Recorder mode */
    val top = new BorderPanel {
      val logo = new CenterAlignedFlowPanel { contents += new Label { icon = LogoSmall } }
      val modeSelection = new GridBagPanel {
        border = titledBorder("Recorder mode")
        layout(modeSelector) = new Constraints
      }

      layout(logo) = West
      layout(modeSelection) = East
    }
    /* Center panel: network config or har import, simulation config, output config & filters */
    val center = new BoxPanel(Orientation.Vertical) {
      val network = new BorderPanel {
        border = titledBorder("Network")

        val localProxyAndHttpsMode = new LeftAlignedFlowPanel {
          contents += new Label("Listening port*: ")
          contents += new Label("    localhost")
          contents += new Label("HTTP/HTTPS")
          contents += localProxyHttpPort
          contents += new Label("    HTTPS mode: ")
          contents += httpsModes
          contents += downloadCertificate
        }

        val outgoingProxy = new LeftAlignedFlowPanel {
          contents += new Label("Outgoing proxy: ")
          contents += new Label("host:")
          contents += outgoingProxyHost
          contents += new Label("HTTP")
          contents += outgoingProxyHttpPort
          contents += new Label("HTTPS")
          contents += outgoingProxyHttpsPort
          contents += new Label("Username")
          contents += outgoingProxyUsername
          contents += new Label("Password")
          contents += outgoingProxyPassword
        }

        layout(localProxyAndHttpsMode) = North
        layout(outgoingProxy) = South
      }
      val har = new BorderPanel {
        border = titledBorder("Http Archive (HAR) Import")
        visible = false

        val fileSelection = new LeftAlignedFlowPanel {
          contents += new Label("HAR File: ")
          contents += harPath
          contents += harFileBrowserButton
        }

        layout(fileSelection) = Center
      }
      val simulationConfig = new BorderPanel {
        border = titledBorder("Simulation Information")

        val config = new BorderPanel {
          val packageName = new LeftAlignedFlowPanel {
            contents += new Label("Package: ")
            contents += simulationPackage
          }
          val className = new LeftAlignedFlowPanel {
            contents += new Label("Class Name*: ")
            contents += simulationClassName
          }

          layout(packageName) = West
          layout(className) = East
        }

        val redirectAndInferOptions = new BorderPanel {
          layout(followRedirects) = West
          layout(inferHtmlResources) = East
        }

        val cacheAndResponseBodiesCheck = new BorderPanel {
          layout(removeConditionalCache) = West
          layout(checkResponseBodies) = East
        }

        layout(config) = North

        layout(redirectAndInferOptions) = West
        layout(automaticReferers) = East
        layout(cacheAndResponseBodiesCheck) = South
      }
      val outputConfig = new BorderPanel {
        border = titledBorder("Output")

        val folderSelection = new LeftAlignedFlowPanel {
          contents += new Label("Output folder*: ")
          contents += outputFolderPath
          contents += outputFolderBrowserButton
        }
        val encoding = new LeftAlignedFlowPanel {
          contents += new Label("Encoding: ")
          contents += outputEncoding
        }

        layout(folderSelection) = North
        layout(encoding) = Center
      }
      val filters = new BorderPanel {
        border = titledBorder("Filters")

        val labelAndStrategySelection = new BorderPanel {
          val label = new Label("Java regular expressions that matches the entire URI")
          label.font_=(label.font.deriveFont(Font.PLAIN))
          val strategy = new RightAlignedFlowPanel {
            contents += new Label("Strategy")
            contents += filterStrategies
          }
          layout(label) = West
          layout(strategy) = East
        }

        val whiteList = new BoxPanel(Orientation.Vertical) {
          contents += whiteListTable
          contents += new CenterAlignedFlowPanel {
            contents += addWhiteListFilter
            contents += removeWhiteListFilter
            contents += clearWhiteListFilters
          }
        }

        val blackList = new BoxPanel(Orientation.Vertical) {
          contents += blackListTable
          contents += new CenterAlignedFlowPanel {
            contents += addBlackListFilter
            contents += removeBlackListFilter
            contents += clearBlackListFilters
            contents += ruleOutStaticResources
          }
        }

        val bothLists = new SplitPane(Orientation.Vertical, whiteList, blackList)
        bothLists.resizeWeight = 0.5

        layout(labelAndStrategySelection) = North
        layout(bothLists) = Center
      }

      contents += network
      contents += har
      contents += simulationConfig
      contents += outputConfig
      contents += filters
    }
    /* Bottom panel: Save preferences & start recording/ export HAR */
    val bottom = new RightAlignedFlowPanel {
      contents += savePreferences
      contents += start
    }

    layout(top) = North
    layout(center) = Center
    layout(bottom) = South
  }

  val scrollPane = new ScrollPane(root)

  contents = scrollPane

  centerOnScreen()

  /*****************************************/
  /**           EVENTS HANDLING           **/
  /*****************************************/

  /* Reactions I: handling filters, save checkbox, table edition and switching between Proxy and HAR mode */
  listenTo(filterStrategies.selection, modeSelector.selection, httpsModes.selection, savePreferences)
  // Backticks are needed to match the components, see section 8.1.5 of Scala spec.
  reactions += {
    case SelectionChanged(`modeSelector`) =>
      modeSelector.selection.item match {
        case Proxy =>
          root.center.network.visible = true
          root.center.har.visible = false
        case Har =>
          root.center.network.visible = false
          root.center.har.visible = true
      }
    case SelectionChanged(`filterStrategies`) =>
      val isNotDisabledStrategy = filterStrategies.selection.item != FilterStrategy.Disabled
      toggleFiltersEdition(isNotDisabledStrategy)
    case SelectionChanged(`httpsModes`) =>
      httpsModes.selection.item match {
        case SelfSignedCertificate =>
          downloadCertificate.visible = false
        case ProvidedKeyStore =>
          downloadCertificate.visible = false
        case GatlingCertificateAuthority =>
          downloadCertificate.visible = true
        case CustomCertificateAuthority =>
          downloadCertificate.visible = false
      }
    case ButtonClicked(`savePreferences`) if !savePreferences.selected =>
      val props = new RecorderPropertiesBuilder
      props.saveConfig(savePreferences.selected)
      RecorderConfiguration.reload(props.build)
      RecorderConfiguration.saveConfig()
  }

  private def toggleFiltersEdition(enabled: Boolean): Unit = {
    whiteListTable.setEnabled(enabled)
    whiteListTable.setFocusable(enabled)
    blackListTable.setEnabled(enabled)
    blackListTable.setFocusable(enabled)
  }

  /* Reactions II: fields validation */
  listenTo(localProxyHttpPort.keys,
    outgoingProxyHost.keys,
    outgoingProxyHttpPort.keys,
    outgoingProxyHttpsPort.keys,
    outputFolderPath.keys,
    simulationPackage.keys,
    simulationClassName.keys)

  private def registerValidators(): Unit = {

    val outgoingProxyPortValidator = (s: String) => outgoingProxyHost.text.isEmpty || isValidPort(s)

    ValidationHelper.registerValidator(localProxyHttpPort, Validator(isValidPort))
    ValidationHelper.registerValidator(outgoingProxyHost, Validator(isNonEmpty, enableOutgoingProxyConfig, disableOutgoingProxyConfig, alwaysValid = true))
    ValidationHelper.registerValidator(outgoingProxyHttpPort, Validator(outgoingProxyPortValidator))
    ValidationHelper.registerValidator(outgoingProxyHttpsPort, Validator(outgoingProxyPortValidator))
    ValidationHelper.registerValidator(outputFolderPath, Validator(isNonEmpty))
    ValidationHelper.registerValidator(simulationPackage, Validator(isValidPackageName))
    ValidationHelper.registerValidator(simulationClassName, Validator(isValidSimpleClassName))
  }

  private def enableOutgoingProxyConfig(c: Component): Unit = {
    publish(keyReleased(outgoingProxyHttpPort))
    publish(keyReleased(outgoingProxyHttpsPort))
    outgoingProxyHttpPort.enabled = true
    outgoingProxyHttpsPort.enabled = true
    outgoingProxyUsername.enabled = true
    outgoingProxyPassword.enabled = true
  }

  private def disableOutgoingProxyConfig(c: Component): Unit = {
    outgoingProxyHttpPort.enabled = false
    outgoingProxyHttpsPort.enabled = false
    outgoingProxyUsername.enabled = false
    outgoingProxyPassword.enabled = false
    // hack for validating outgoingProxyHttpPort and outgoingProxyHttpsPort
    outgoingProxyHttpPort.text = ""
    outgoingProxyHttpsPort.text = ""
    outgoingProxyUsername.text = ""
    outgoingProxyPassword.text = ""
    publish(keyReleased(outgoingProxyHttpPort))
    publish(keyReleased(outgoingProxyHttpsPort))
  }

  private def blackListStaticResources(): Unit = {
    List(
      """.*\.js""",
      """.*\.css""",
      """.*\.gif""",
      """.*\.jpeg""",
      """.*\.jpg""",
      """.*\.ico""",
      """.*\.woff""",
      """.*\.(t|o)tf""",
      """.*\.png""").foreach(blackListTable.addRow)

    filterStrategies.selection.item = BlacklistFirst
  }

  reactions += {
    case KeyReleased(field, _, _, _) =>
      updateValidationStatus(field.asInstanceOf[TextField])
      start.enabled = ValidationHelper.validationStatus
  }

  def selectedMode = modeSelector.selection.item

  def harFilePath = harPath.text

  def updateHarFilePath(path: Option[String]): Unit = path.foreach(harPath.text = _)

  def downloadGatlingCertificate(path: String): Unit = {
    val gatlingCertificate = classpathResourceAsStream(GatlingCAFactory.DefaultCACrtFile)
    gatlingCertificate.copyTo(string2path(path).outputStream)
    Dialog.showMessage(
      title = "Download successful",
      message =
        s"""|Gatling's CA was successfully saved to
           |$path .""".stripMargin)
  }

  /****************************************/
  /**           CONFIGURATION            **/
  /****************************************/

  /**
   * Configure fields, checkboxes, filters... based on the current Recorder configuration
   */
  private def populateItemsFromConfiguration(): Unit = {
    localProxyHttpPort.text = configuration.proxy.port.toString

    configuration.proxy.outgoing.host.map { proxyHost =>
      outgoingProxyHost.text = proxyHost
      outgoingProxyHttpPort.text = configuration.proxy.outgoing.port.map(_.toString).orNull
      outgoingProxyHttpsPort.text = configuration.proxy.outgoing.sslPort.map(_.toString).orNull
      outgoingProxyUsername.text = configuration.proxy.outgoing.username.orNull
      outgoingProxyPassword.text = configuration.proxy.outgoing.password.orNull
      outgoingProxyHttpPort.enabled = true
      outgoingProxyHttpsPort.enabled = true
      outgoingProxyUsername.enabled = true
      outgoingProxyPassword.enabled = true
    }
    configuration.core.pkg.trimToOption.map(simulationPackage.text = _)
    simulationClassName.text = configuration.core.className
    filterStrategies.selection.item = configuration.filters.filterStrategy
    followRedirects.selected = configuration.http.followRedirect
    inferHtmlResources.selected = configuration.http.inferHtmlResources
    removeConditionalCache.selected = configuration.http.removeConditionalCache
    checkResponseBodies.selected = configuration.http.checkResponseBodies
    automaticReferers.selected = configuration.http.automaticReferer
    configuration.filters.blackList.patterns.foreach(blackListTable.addRow)
    configuration.filters.whiteList.patterns.foreach(whiteListTable.addRow)
    outputFolderPath.text = configuration.core.outputFolder
    outputEncoding.selection.item = CharsetHelper.charsetNameToLabel(configuration.core.encoding)
    savePreferences.selected = configuration.core.saveConfig

  }

  /**
   * Reload configuration from the content of the configuration frame
   * and start recording
   */
  private def reloadConfigurationAndStart(): Unit = {
    // clean up filters
    whiteListTable.cleanUp()
    blackListTable.cleanUp()

    val filterValidationFailures =
      if (filterStrategies.selection.item == FilterStrategy.Disabled)
        Nil
      else
        whiteListTable.validate ::: blackListTable.validate

    if (filterValidationFailures.nonEmpty) {
      frontend.handleFilterValidationFailures(filterValidationFailures)

    } else {

      val props = new RecorderPropertiesBuilder

      // Local proxy
      props.localPort(Try(localProxyHttpPort.text.toInt).getOrElse(0))

      // Outgoing proxy
      outgoingProxyHost.text.trimToOption match {
        case Some(host) =>
          props.proxyHost(host)
          props.proxyPort(outgoingProxyHttpPort.text.toInt)
          props.proxySslPort(outgoingProxyHttpsPort.text.toInt)
          outgoingProxyUsername.text.trimToOption.foreach(props.proxyUsername)
          outgoingProxyPassword.text.trimToOption.foreach(props.proxyPassword)

        case None =>
          props.proxyHost("")
          props.proxyPort(0)
          props.proxySslPort(0)
          props.proxyUsername("")
          props.proxyPassword("")
      }

      // Filters
      props.filterStrategy(filterStrategies.selection.item.toString)
      props.whitelist(whiteListTable.getRegexs)
      props.blacklist(blackListTable.getRegexs)

      // Simulation config
      props.simulationPackage(simulationPackage.text)
      props.simulationClassName(simulationClassName.text.trim)
      props.followRedirect(followRedirects.selected)
      props.inferHtmlResources(inferHtmlResources.selected)
      props.removeConditionalCache(removeConditionalCache.selected)
      props.checkResponseBodies(checkResponseBodies.selected)
      props.automaticReferer(automaticReferers.selected)
      props.simulationOutputFolder(outputFolderPath.text.trim)
      props.encoding(CharsetHelper.labelToCharsetName(outputEncoding.selection.item))
      props.saveConfig(savePreferences.selected)

      RecorderConfiguration.reload(props.build)

      if (savePreferences.selected) {
        RecorderConfiguration.saveConfig()
      }

      frontend.startRecording()
    }
  }
}
