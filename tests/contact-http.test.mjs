import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const port = 19371;
const base = `http://127.0.0.1:${port}`;
const smtpHost = process.env.TEST_SMTP_HOST || '127.0.0.1';
const mailhog = process.env.TEST_MAILHOG_URL || 'http://127.0.0.1:8026';
const data = {name:'Camille Ndem',email:'camille@example.test',subject:`Contact integration ${Date.now()}`,message:'Please arrange a business verification walkthrough.','cf-turnstile-response':'XXXX.DUMMY.TOKEN.XXXX'};

async function runServer(overrides, check) {
  const directory = await mkdtemp(join(tmpdir(), 'formsink-http-'));
  const server = spawn(process.execPath, ['--import','./tests/siteverify-fixture.mjs','src/index.js'], {env:{...process.env,PORT:String(port),DATA_DIR:directory,API_KEY:'local-test-api-key',ADMIN_PASSWORD:'local-test-password',TURNSTILE_REQUIRED_FORMS:'test,contact,request-demo',TURNSTILE_SECRET_KEY:'1x0000000000000000000000000000000AA',TURNSTILE_HOSTNAMES:'localhost',NOTIFICATION_COPY_TO:'folks@whilesmart.com',SMTP_HOST:smtpHost,SMTP_PORT:'1026',SMTP_USER:'',SMTP_PASS:'',SMTP_FROM:'contact@example.test',SITEVERIFY_FIXTURE:'tests/fixtures/siteverify-success.json',...overrides},stdio:'pipe'});
  let output = '';
  server.stderr.on('data', chunk => output += chunk);
  try {
    let ready = false;
    for (let i=0;i<60;i++) {
      try {ready=(await fetch(base+'/health')).ok;} catch {}
      if(ready)break;
      await new Promise(resolve=>setTimeout(resolve,100));
    }
    assert.ok(ready,output);
    for (const slug of ['test','contact','request-demo']) {
      const response=await fetch(base+'/api/forms',{method:'POST',headers:{'Content-Type':'application/json','X-API-Key':'local-test-api-key'},body:JSON.stringify({slug,name:'Credflare contact',notifyEmail:'support@credflare.net',allowedOrigins:['http://localhost:4321']})});
      assert.equal(response.status,201);
    }
    await check();
  } finally {
    server.kill();
    await new Promise(resolve=>server.once('exit',resolve));
  }
}
const submit=(slug,body)=>fetch(base+'/api/f/'+slug,{method:'POST',headers:{'Content-Type':'application/json',Origin:'http://localhost:4321'},body:JSON.stringify(body)});
const stored=async()=> (await fetch(base+'/api/submissions/test',{headers:{'X-API-Key':'local-test-api-key'}})).json();

test('Protected submissions validate before storage and deliver to both recipients',async()=>{
 await runServer({},async()=>{
  assert.equal((await submit('test',{...data,email:'invalid'})).status,422);
  assert.equal((await submit('test',{...data,'cf-turnstile-response':''})).status,400);
  assert.equal((await submit('contact',data)).status,400);
  assert.equal((await submit('request-demo',{...data,company:'Aster Field Botanics'})).status,400);
  assert.deepEqual(await stored(),[]);
  const response=await submit('test',data);
  assert.equal(response.status,201);
  assert.equal((await response.json()).success,true);
  const rows=await stored();assert.equal(rows.length,1);
  assert.equal(rows[0].data['cf-turnstile-response'],undefined);
  const inbox=await (await fetch(mailhog+'/api/v2/messages?limit=100')).json();
  const mail=inbox.items.find(item=>item.Content.Body.includes(data.subject));
  assert.ok(mail,'SMTP message must reach Mailhog');
  assert.deepEqual(mail.To.map(address=>`${address.Mailbox}@${address.Domain}`).sort(),['folks@whilesmart.com','support@credflare.net']);
 });
});
test('Failed Cloudflare validation creates no submission',async()=>{
 await runServer({SITEVERIFY_FIXTURE:'tests/fixtures/siteverify-failure.json'},async()=>{
  assert.equal((await submit('test',data)).status,400);assert.deepEqual(await stored(),[]);
 });
});
test('Wrong hostname and missing configuration fail closed',async()=>{
 for(const config of [{TURNSTILE_HOSTNAMES:'credflare.net'},{TURNSTILE_SECRET_KEY:''}])await runServer(config,async()=>{
  assert.equal((await submit('test',data)).status,config.TURNSTILE_SECRET_KEY===''?503:400);assert.deepEqual(await stored(),[]);
 });
});
test('SMTP failure preserves the submission without reporting success',async()=>{
 await runServer({SMTP_PORT:'1'},async()=>{
  const response=await submit('test',data);assert.equal(response.status,502);
  assert.match((await response.json()).error,/saved/);assert.equal((await stored()).length,1);
 });
});
