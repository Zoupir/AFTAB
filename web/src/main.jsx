import React, {useEffect, useState} from 'react'
import QRCode from 'qrcode'
import {createRoot} from 'react-dom/client'
import './style.css'

const t={
 fa:{title:'مدیریت آفتاب',sub:'پیش‌نمایش ایمن پنل مدیریت',login:'ورود مدیر',loginHelp:'توکن مدیریت را وارد کنید. این توکن فقط در حافظه این صفحه نگه داشته می‌شود.',token:'توکن مدیریت',enter:'ورود',logout:'خروج',new:'حساب جدید',name:'شناسه حساب',device:'دستگاه',days:'روز اعتبار',volume:'حجم (گیگابایت)',create:'ساخت حساب',accounts:'حساب‌ها',state:'وضعیت',valid:'ثبت‌شده در Xray',disabled:'غیرفعال',waiting:'در انتظار ثبت در هسته',deactivate:'غیرفعال‌کردن',oneTime:'توکن اشتراک فقط یک‌بار نمایش داده می‌شود. آن را در اختیار افراد ناشناس قرار ندهید.',pending:'ثبت کاربر در دیتابیس به معنی اتصال نیست. تنها زمانی که وضعیت «ثبت‌شده در Xray» نمایش داده شود، هسته آن را پذیرفته است. سرویس اشتراک عمومی هنوز راه‌اندازی نشده است.',none:'هنوز حسابی ساخته نشده است.',loading:'در حال بارگذاری...',error:'خطای ارتباط یا احراز هویت',expires:'تاریخ انقضا',quota:'مصرف / سهمیه',copy:'کپی توکن',copied:'کپی شد',connectLink:'لینک اتصال VLESS',connectCopy:'کپی لینک اتصال',connectQR:'QR اتصال',notReady:'تا زمان ثبت واقعی در هسته، لینک اتصال ساخته نمی‌شود.',confirm:'این حساب غیرفعال شود؟',win:'ویندوز',android:'اندروید',other:'سایر',language:'English',unknown:'نامشخص'},
 en:{title:'AFTAB Control',sub:'Secure control-plane preview',login:'Administrator login',loginHelp:'Enter the administrator token. It remains in page memory only.',token:'Admin token',enter:'Sign in',logout:'Sign out',new:'Create account',name:'Account ID',device:'Device',days:'Days',volume:'Quota (GB)',create:'Create account',accounts:'Accounts',state:'State',valid:'Registered in Xray',disabled:'Disabled',waiting:'Awaiting engine registration',deactivate:'Disable',oneTime:'The subscription token is shown once. Do not share it publicly.',pending:'Creating an account in SQLite does not activate a connection. Only “Registered in Xray” confirms engine acceptance; the public subscription service is not deployed yet.',none:'No accounts yet.',loading:'Loading...',error:'Network or authorization error',expires:'Expires',quota:'Used / quota',copy:'Copy token',copied:'Copied',connectLink:'VLESS connection URI',connectCopy:'Copy connection URI',connectQR:'Connection QR',notReady:'The connection URI is unavailable until the engine registers this user.',confirm:'Disable this account?',win:'Windows',android:'Android',other:'Other',language:'فارسی',unknown:'Unknown'}
}
function App(){
 const [vless,setVless]=useState(''),[qr,setQr]=useState(''),[lang,setLang]=useState('fa'),[token,setToken]=useState(''),[auth,setAuth]=useState(''),[accounts,setAccounts]=useState([]),[msg,setMsg]=useState(''),[newToken,setNewToken]=useState(''),[newName,setNewName]=useState(''),[busy,setBusy]=useState(false),[name,setName]=useState(''),[device,setDevice]=useState('windows'),[days,setDays]=useState(30),[gb,setGb]=useState(30)
 const l=t[lang]
 const request=async(path,method='GET',body)=>{
  const response=await fetch(path,{method,headers:{'Authorization':'Bearer '+auth,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined,cache:'no-store'})
  if(!response.ok)throw new Error('HTTP '+response.status)
  return response.json()
 }
 useEffect(()=>{let alive=true;if(!vless){setQr('');return}QRCode.toDataURL(vless,{errorCorrectionLevel:'M',margin:2,width:222}).then(data=>{if(alive)setQr(data)}).catch(()=>{if(alive)setQr('')});return()=>{alive=false}},[vless])
 const refresh=async()=>{setBusy(true);try{setAccounts(await request('/api/v1/users'));setMsg('')}catch(e){setMsg(l.error+' ('+e.message+')')}finally{setBusy(false)}}
 useEffect(()=>{if(auth)refresh()},[auth])
 const signin=async(e)=>{e.preventDefault();if(!token.trim())return;setAuth(token.trim());setToken('')}
 const create=async(e)=>{e.preventDefault();setBusy(true);setMsg('');setNewToken('');setVless('');try{
  const data=await request('/api/v1/users','POST',{Name:name.trim(),Device:device,Days:Number(days),GB:Number(gb)})
  setNewToken(data.subscription_token_once);setVless(data.vless_uri||'');setNewName(data.account.name);setName('');if(data.provisioning!=='registered_by_agent'){setMsg(lang==='fa'?'ثبت در هسته انجام نشده؛ حساب هنوز قابل اتصال نیست.':'Engine provisioning is not complete; the account cannot connect yet.')}
  setAccounts(await request('/api/v1/users'))
 }catch(e){setMsg(l.error+' ('+e.message+')')}finally{setBusy(false)}}
 const disable=async(a)=>{if(!confirm(l.confirm))return;try{await request('/api/v1/users/'+encodeURIComponent(a.id)+'/disable','POST');await refresh()}catch(e){setMsg(l.error+' ('+e.message+')')}}
 const money=n=>(n/1073741824).toFixed(2)
 return <div className="app" dir={lang==='fa'?'rtl':'ltr'}>
  <header className="top"><div className="brand"><div className="sun">A</div><div><strong>AFTAB</strong><small>{l.sub}</small></div></div><button className="link" onClick={()=>setLang(lang==='fa'?'en':'fa')}>{l.language}</button></header>
  {!auth?<main className="signin card"><h1>{l.login}</h1><p className="hint">{l.loginHelp}</p><form onSubmit={signin}><label>{l.token}<input type="password" autoComplete="off" value={token} onChange={e=>setToken(e.target.value)} minLength={32} required/></label><button type="submit">{l.enter}</button></form></main>:
  <main className="container"><div className="pageHeading"><div><span className="overline">CONTROL PLANE / PREVIEW</span><h1>{l.title}</h1></div><button className="secondary" onClick={()=>{setAuth('');setAccounts([]);setNewToken('');setVless('');setQr('')}}>{l.logout}</button></div>
   <div className="warning"><strong>ENGINE NOT PROVISIONED</strong><p>{l.pending}</p></div>
   <div className="layout">
    <section className="card"><h2>{l.new}</h2><form onSubmit={create} className="form">
     <label>{l.name}<input value={name} onChange={e=>setName(e.target.value)} pattern="[A-Za-z0-9][A-Za-z0-9._-]{0,63}" required maxLength="64" placeholder="friend-phone"/></label>
     <label>{l.device}<select value={device} onChange={e=>setDevice(e.target.value)}><option value="windows">{l.win}</option><option value="android">{l.android}</option><option value="other">{l.other}</option></select></label>
     <div className="pair"><label>{l.days}<input type="number" min="1" max="3650" value={days} onChange={e=>setDays(e.target.value)} required /></label><label>{l.volume}<input type="number" min="1" max="100000" value={gb} onChange={e=>setGb(e.target.value)} required /></label></div>
     <button type="submit" disabled={busy}>{l.create}</button>
    </form>
    {newToken&&<div className="success"><strong>{newName}</strong><p>{l.oneTime}</p><code>{newToken}</code><button className="secondary" onClick={async()=>{await navigator.clipboard.writeText(newToken);setMsg(l.copied)}}>{l.copy}</button>{vless?<div className="connection"><h3>{l.connectLink}</h3><code>{vless}</code><button className="secondary" onClick={async()=>{await navigator.clipboard.writeText(vless);setMsg(l.copied)}}>{l.connectCopy}</button>{qr&&<div className="qr"><img src={qr} width="222" height="222" alt={l.connectQR}/><span>{l.connectQR}</span></div>}</div>:<p className="fine">{l.notReady}</p>}</div>}
    </section>
    <section className="card wide"><div className="sectionTitle"><h2>{l.accounts}</h2><span className="count">{accounts.length}</span></div>
      {msg&&<div className="message" role="alert">{msg}</div>}
      {busy&&accounts.length===0?<p>{l.loading}</p>:accounts.length===0?<p className="hint">{l.none}</p>:
      <div className="tableScroll"><table><thead><tr><th>{l.name}</th><th>{l.device}</th><th>{l.expires}</th><th>{l.quota}</th><th>{l.state}</th><th></th></tr></thead>
      <tbody>{accounts.map(a=><tr key={a.id}><td><strong>{a.name}</strong></td><td>{a.device}</td><td className="mono">{a.expires_at.slice(0,10)}</td><td className="mono">{money(a.used_bytes)} / {money(a.quota_bytes)}</td><td><span className={a.disabled||!a.provisioned?'bad':'good'}>{a.disabled?l.disabled:a.provisioned?l.valid:l.waiting}</span></td><td>{!a.disabled&&<button className="small secondary" onClick={()=>disable(a)}>{l.deactivate}</button>}</td></tr>)}</tbody></table></div>}
    </section>
   </div>
   <footer>AFTAB 1.0 · PRIVATE CONTROL PLANE · PREVIEW</footer>
  </main>}
 </div>
}
createRoot(document.getElementById('root')).render(<App/>)
