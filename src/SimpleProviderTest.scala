import java.security.Security
import java.security.Provider
import org.bouncycastle.jce.provider.BouncyCastleProvider

object SimpleProviderTest {
	def main(args: Array[String]) {
		val providerName = "BC"
		Security.addProvider(new BouncyCastleProvider)
		Security.getProvider(providerName) match {
			case a: Provider => println(providerName + " is installed.")
			case null => println(providerName + " is not installed")
		}
	}
}
