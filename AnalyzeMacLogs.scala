import scala.util.Try

import sys.process._

/**
  * Created by xan0 on 10/29/17.
  */
object AnalyzeMacLogs {

  def main( args: Array[String] ): Unit = {

    /** Grab event logs command */
    val setHost = setHostname()
    setHost.foreach(println)
    val wifi = getWifi()
    wifi.foreach(println)
    val failedLogins = failedLogins()
    val errors = errorLogs()
    val installed = installed()
    val sandbox = sandboxViolation()
    val sudo = sudoCmds()
    val countryCodes = countryCode()
    val ssh = sshCmds()
    val passwordCmds = passwordCmd()

  } // END main()

  private[this] def getWifi(): Stream[String] = {
   val wifi = Seq("log", "show" ,"--predicate", "'(eventMessage CONTAINS \"Airportd\")'")

    wifi.lineStream
  } // END getWifi()

  private[this] def failedLogins(): Stream[String] = {
    val failedLogins = Seq( "log", "show", "--predicate", "'(eventMessage CONTAINS \"ODRecordVerifyPassword\")'")

    failedLogins.lineStream
  } // END failedLogins()

  private[this] def errorLogs(): Stream[String] = {
    val errors = Seq( "log", "show", "--predicate", "'(eventMessage CONTAINS \"Error\")'")

    errors.lineStream
  } // END errorLogs()

  /** Testing another style so we can grep it. */
  private[this] def setHostname(): Vector[String]  = {
    val setHost = "log show --predicate '(eventMessage CONTAINS \"setting hostname to\")'"
    val stream = setHost.lineStream_!

    stream.toVector
  } // END setHostname()

  private[this] def installed(): Stream[String]  = {
    val installed = Seq( "log", "show", "--predicate", "'(eventMessage CONTAINS \"installed\")'" , "#|", "grep", "-v", "\"storedassetd\"" )

    installed.lineStream
  } // END installed()

  private[this] def sandboxViolation(): Stream[String]  = {
    val cmd = Seq( "log", "show", "--predicate", "'(eventMessage CONTAINS \"SandboxViolation\")'" )

    cmd.lineStream
  } // END installed()

  private[this] def sudoCmds(): Stream[String]  = {
    val sudo = Seq( "log", "show", "--predicate", "'(eventMessage CONTAINS \"sudo\")'" )

    sudo.lineStream
  } // END installed()

  private[this] def countryCode(): Stream[String]  = {
    val cmd = Seq( "log", "show", "--predicate", "'(eventMessage CONTAINS \"country code set to\")'" )

    cmd.lineStream
  } // END installed()

  private[this] def sshCmds(): Stream[String]  = {
    val cmd = Seq( "log", "show", "--predicate", "'(eventMessage CONTAINS \"ssh\")'" )

    cmd.lineStream
  } // END installed()

  private[this] def passwordCmd(): Stream[String]  = {
    val cmd = Seq( "log", "show", "--predicate", "'(eventMessage CONTAINS \"password\")'" )

    cmd.lineStream
  } // END installed()

} // END AnalyzeMacLogs object
