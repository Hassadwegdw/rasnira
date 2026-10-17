import com.rasnira.app.ScanEngine;
import java.nio.charset.StandardCharsets;

public final class ScanEngineTest {
  private static void check(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
  public static void main(String[] args) {
    ScanEngine.Findings f=ScanEngine.analyze("EICAR X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\nsecret=abcdef123");
    check(f.eicar,"EICAR signature detected"); check(f.secret,"secret detected");
    check(!ScanEngine.analyze("// secret=abcdef123\n/* eval(x) */\nString s=\"eval(x) secret=abcdef123\";").secret,"secret comments/literals ignored");
    check(!ScanEngine.analyze("// eval(x)\nString s=\"eval(x)\";").dangerous,"eval comments/literals ignored");
    check(ScanEngine.analyze("eval (x);").dangerous,"actual eval detected");
    check("hello".equals(ScanEngine.decode(new byte[]{(byte)0xEF,(byte)0xBB,(byte)0xBF,'h','e','l','l','o'})),"UTF-8 BOM");
    check("Hi".equals(ScanEngine.decode(new byte[]{(byte)0xFF,(byte)0xFE,'H',0,'i',0})),"UTF-16LE BOM");
    check("Hi".equals(ScanEngine.decode(new byte[]{(byte)0xFE,(byte)0xFF,0,'H',0,'i'})),"UTF-16BE BOM");
    check(ScanEngine.analyze("const password = \"not-real-secret-value\";").secret,"quoted secret assignment detected");
    check(!ScanEngine.analyze("const note = `eval(x)`;").dangerous,"template literal ignored");
    check(ScanEngine.analyze("const note = `hello`; eval(x);").dangerous,"code after template is scanned");
    System.out.println("ScanEngineTest: OK");
  }
}
