package com.rasnira.app;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/** Pure Java, bounded-text inspection helpers. Never returns matched text or secret values. */
public final class ScanEngine {
  public static final int MAX_TEXT_BYTES = 2 * 1024 * 1024;
  private static final String EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
  private static final Pattern SECRET = Pattern.compile("(?i)(?:password|passwd|api[_-]?key|secret)\\s*[:=]\\s*[^\\s]{6,}");
  private static final Pattern DANGEROUS = Pattern.compile("(?i)(?:powershell\\s+-enc|cmd\\s*/c|/bin/(?:sh|bash)\\s+-c|curl\\s+[^\\n]+\\|\\s*(?:sh|bash)|eval\\s*\\(|document\\.cookie|javascript:)");
  private ScanEngine() {}
  public static final class Findings {
    public final boolean eicar, secret, dangerous;
    Findings(boolean e, boolean s, boolean d) { eicar=e; secret=s; dangerous=d; }
  }
  public static Findings analyze(String text) {
    String code = stripCommentsAndLiterals(text == null ? "" : text);
    boolean secret=false;
    java.util.regex.Matcher matches=SECRET.matcher(text==null?"":text);
    while(matches.find()){String prefix=code.substring(matches.start(),Math.min(code.length(),matches.start()+12));if(Pattern.compile("(?i)^(?:password|passwd|api[_-]?key|secret)\\b").matcher(prefix).find()){secret=true;break;}}
    return new Findings((text != null && text.contains(EICAR)), secret, DANGEROUS.matcher(code).find());
  }
  /** Detect common UTF-8/UTF-16 BOMs; otherwise accept UTF-8 with Windows-1252 fallback. */
  public static String decode(byte[] b) {
    if (b == null) return "";
    if (b.length >= 2 && (b[0]&255)==0xFF && (b[1]&255)==0xFE) return new String(b,2,b.length-2,StandardCharsets.UTF_16LE);
    if (b.length >= 2 && (b[0]&255)==0xFE && (b[1]&255)==0xFF) return new String(b,2,b.length-2,StandardCharsets.UTF_16BE);
    if (b.length >= 3 && (b[0]&255)==0xEF && (b[1]&255)==0xBB && (b[2]&255)==0xBF) return new String(b,3,b.length-3,StandardCharsets.UTF_8);
    String s = new String(b, StandardCharsets.UTF_8);
    return s.indexOf('\uFFFD') >= 0 ? new String(b, Charset.forName("windows-1252")) : s;
  }
  // Replace comments and quoted strings with spaces while preserving line breaks and code tokens.
  private static String stripCommentsAndLiterals(String s) {
    StringBuilder out=new StringBuilder(s.length()); int state=0; // 0 code, 1 single, 2 double, 3 line, 4 block
    for(int i=0;i<s.length();i++) { char c=s.charAt(i), n=i+1<s.length()?s.charAt(i+1):0;
      if(state==0) {
        if(c=='\''||c=='"'||c=='`'){state=c=='\''?1:(c=='`'?5:2);out.append(' ');}
        else if(c=='/'&&n=='/'){state=3;out.append("  ");i++;}
        else if(c=='#'){state=3;out.append(' ');}
        else if(c=='/'&&n=='*'){state=4;out.append("  ");i++;}
        else out.append(c);
      } else if(state==1||state==2||state==5) { out.append(c=='\n'||c=='\r'?c:' '); if(c=='\\'&&i+1<s.length()){out.append(' ');i++;} else if((state==1&&c=='\'')||(state==2&&c=='"')||(state==5&&c=='`'))state=0; }
      else if(state==3){ if(c=='\n'||c=='\r'){out.append(c);state=0;}else out.append(' '); }
      else { if(c=='*'&&n=='/'){out.append("  ");i++;state=0;}else out.append(c=='\n'||c=='\r'?c:' '); }
    } return out.toString();
  }
}
