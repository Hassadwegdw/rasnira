import {analyzeFiles} from './scanner.js';
self.onmessage=async event=>{
 const {id,files}=event.data||{};
 try{
  if(!Array.isArray(files))throw Error('قائمة الملفات غير صالحة');
  const reports=[];
  for(let index=0;index<files.length;index++){
   reports.push(analyzeFiles([files[index]]));
   self.postMessage({id,type:'progress',done:index+1,total:files.length});
   await new Promise(resolve=>setTimeout(resolve,0));
  }
  self.postMessage({id,type:'complete',reports});
 }catch(error){self.postMessage({id,type:'error',message:error?.message||'تعذر التحليل'})}
};
