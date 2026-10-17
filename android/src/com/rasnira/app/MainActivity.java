package com.rasnira.app;

import android.app.Activity;
import android.os.Bundle;
import android.content.Intent;
import android.net.Uri;
import android.view.Gravity;
import android.view.View;
import android.widget.*;
import android.graphics.Color;
import java.io.*;
import java.security.MessageDigest;
import java.util.*;

public class MainActivity extends Activity {
  static final int PICK=41; static final long MAX_FILE=20L*1024*1024, MAX_TOTAL=100L*1024*1024;
  LinearLayout root; TextView status, output; Button pick;
  @Override public void onCreate(Bundle b){super.onCreate(b); build();}
  void build(){
    root=new LinearLayout(this); root.setOrientation(1); root.setPadding(24,28,24,24); root.setBackgroundColor(Color.rgb(247,249,252)); root.setLayoutDirection(View.LAYOUT_DIRECTION_RTL);
    ScrollView sc=new ScrollView(this); LinearLayout content=new LinearLayout(this); content.setOrientation(1); content.setPadding(0,0,0,20); sc.addView(content);
    TextView title=text("رَصنيرا",30,true); content.addView(title); content.addView(text("فحص محلي أولي للملفات",17,true));
    TextView intro=text("اختر ملفاً أو أكثر من جهازك. تتم القراءة والفحوصات على هذا الجهاز فقط؛ لا تُرفع الملفات ولا تُنفّذ.",16,false); intro.setPadding(0,18,0,14); content.addView(intro);
    TextView limit=text("الحدود: 20 ميغابايت لكل ملف، و100 ميغابايت للمجموعة. تُحسب بصمة SHA-256 من كامل الملف؛ أما فحص الأنماط النصية فيقتصر على أول 2 ميبيبايت فقط. لا يوجد فحص للموقع أو الشبكة ولا تصدير للتقرير. هذه الفحوصات محدودة ولا تثبت سلامة الملف، ولا تصل إلى بيانات التطبيقات الأخرى.",14,false); limit.setPadding(14,14,14,14); limit.setBackgroundColor(Color.rgb(230,239,249)); content.addView(limit);
    pick=new Button(this); pick.setText("اختيار ملفات للفحص"); content.addView(pick); pick.setOnClickListener(new View.OnClickListener(){public void onClick(View v){choose();}});
    status=text("جاهز — لم يتم فحص أي ملف.",15,true); status.setPadding(0,20,0,8); content.addView(status);
    output=text("",14,false); content.addView(output); root.addView(sc); setContentView(root);
  }
  TextView text(String s,int size,boolean bold){TextView t=new TextView(this);t.setText(s);t.setTextSize(size);t.setTextColor(Color.rgb(28,43,60));t.setGravity(Gravity.RIGHT);if(bold)t.setTypeface(null,1);t.setPadding(0,6,0,6);return t;}
  void choose(){Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);i.setType("*/*");i.putExtra(Intent.EXTRA_ALLOW_MULTIPLE,true);i.addCategory(Intent.CATEGORY_OPENABLE);startActivityForResult(i,PICK);}
  @Override protected void onActivityResult(int req,int res,Intent data){super.onActivityResult(req,res,data);if(req!=PICK||res!=RESULT_OK||data==null)return; ArrayList<Uri> list=new ArrayList<>(); if(data.getClipData()!=null){for(int n=0;n<data.getClipData().getItemCount();n++)list.add(data.getClipData().getItemAt(n).getUri());}else if(data.getData()!=null)list.add(data.getData()); if(list.isEmpty())return; pick.setEnabled(false);status.setText("جارٍ الفحص محلياً… 0 من "+list.size()); output.setText(""); final ArrayList<Uri> chosen=list; new Thread(new Runnable(){public void run(){scan(chosen);}}).start(); }
  void scan(ArrayList<Uri> files){
    final StringBuilder report=new StringBuilder(); long total=0; int completed=0;
    for(int index=0;index<files.size();index++) { final int position=index+1; Uri u=files.get(index); String name="الملف #"+position;
      try {
        android.database.Cursor c=getContentResolver().query(u,new String[]{"_display_name","_size"},null,null,null);
        if(c!=null){try{if(c.moveToFirst()){int ix=c.getColumnIndex("_size");if(ix>=0&&!c.isNull(ix)&&c.getLong(ix)>MAX_FILE){report.append("تجاوز الملف الحد المسموح (20 ميغابايت).\n\n");completed++;updateProgress(position,files.size());continue;}}}finally{c.close();}}
        MessageDigest md=MessageDigest.getInstance("SHA-256"); ByteArrayOutputStream sample=new ByteArrayOutputStream(); long count=0; byte[] buf=new byte[8192];
        InputStream in=getContentResolver().openInputStream(u); if(in==null)throw new IOException();
        try {int n;while((n=in.read(buf))!=-1){count+=n;total+=n;if(count>MAX_FILE||total>MAX_TOTAL)break;md.update(buf,0,n);if(sample.size()<ScanEngine.MAX_TEXT_BYTES)sample.write(buf,0,Math.min(n,ScanEngine.MAX_TEXT_BYTES-sample.size()));}} finally {in.close();}
        if(count>MAX_FILE||total>MAX_TOTAL){report.append("توقف الفحص لتجاوز حد الحجم المسموح.\n\n");updateProgress(position,files.size());break;}
        ScanEngine.Findings findings=ScanEngine.analyze(ScanEngine.decode(sample.toByteArray())); StringBuilder flags=new StringBuilder();
        if(findings.eicar)flags.append(" • توقيع اختبار EICAR (اختبار آمن؛ ليس فيروساً حقيقياً)");
        if(findings.secret)flags.append(" • احتمال وجود سر/كلمة مرور (القيمة محجوبة)");
        if(findings.dangerous)flags.append(" • نمط نصي خطِر محتمل");
        StringBuilder hex=new StringBuilder();for(byte b:md.digest())hex.append(String.format(Locale.US,"%02x",b));
        report.append(name).append("\nSHA-256: ").append(hex).append("\n").append(flags.length()==0?"لا توجد مطابقة للأنماط المحدودة التي يفحصها التطبيق؛ هذا لا يثبت أن الملف آمن.":"تنبيه:").append(flags).append("\n\n"); completed++;
      } catch(Exception e){report.append("تعذّر فحص أحد الملفات بسبب خطأ في القراءة أو المعالجة.\n\n");completed++;}
      updateProgress(position,files.size());
    }
    final String out=report.toString();final int d=completed;runOnUiThread(new Runnable(){public void run(){output.setText(out);status.setText("اكتمل الفحص المحلي — ملفات عولجت: "+d+" من "+files.size());pick.setEnabled(true);}});
  }
  void updateProgress(final int current,final int total){runOnUiThread(new Runnable(){public void run(){status.setText("جارٍ الفحص محلياً — "+current+" من "+total);}});}
}
