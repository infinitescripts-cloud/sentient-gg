const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
let projects = [], builds = [], licenses = [], audit = [];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(url, options={}) {
  const res = await fetch('/api'+url, { credentials:'same-origin', headers:{'Content-Type':'application/json',...(options.headers||{})}, ...options });
  const data = res.status === 204 ? null : await res.json().catch(()=>({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}
function notice(message, error=false) {
  const el=$('#notice'); el.textContent=message; el.classList.remove('hidden','error-notice');
  if(error) el.classList.add('error-notice');
  window.scrollTo({top:0,behavior:'smooth'});
  clearTimeout(notice.timer); notice.timer=setTimeout(()=>el.classList.add('hidden'),5000);
}
function empty(msg){return `<div class="empty">${esc(msg)}</div>`}
function showPage(name) {
  $$('.page').forEach(p=>p.classList.toggle('hidden',p.id!==`page-${name}`));
  $$('.nav').forEach(b=>b.classList.toggle('active',b.dataset.page===name));
  const labels={overview:'Overview',projects:'Projects',protect:'Protect script',builds:'Build history',licenses:'Licenses',audit:'Audit log',settings:'Settings'};
  $('#pageTitle').textContent=labels[name]||'Overview'; $('#crumb').textContent=(labels[name]||'Overview').toUpperCase();
  $('.sidebar').classList.remove('open');
  if(name==='overview') renderOverview(); if(name==='projects') renderProjects(); if(name==='protect') fillProjectSelect(); if(name==='builds') renderBuilds(); if(name==='licenses') renderLicenses(); if(name==='audit') renderAudit();
}
async function refresh() {
  [projects,builds,licenses,audit]=await Promise.all([
    api('/projects'),api('/builds'),api('/licenses'),api('/audit')
  ]);
  renderOverview();
}
function projectCard(p) {
 return `<article class="project-card"><div class="project-head"><div class="project-symbol">▣</div><div><h4>${esc(p.name)}</h4><small>Created ${new Date(p.createdAt).toLocaleDateString()}</small></div></div><p>${esc(p.description||'No description added.')}</p><div class="card-actions"><button class="small-btn" data-build-for="${esc(p.id)}">Protect script →</button><button class="small-btn" data-edit-project="${esc(p.id)}">Edit</button><button class="small-btn danger" data-delete-project="${esc(p.id)}">Delete</button></div></article>`;
}
function renderOverview(){
 $('#statProjects').textContent=projects.length; $('#statBuilds').textContent=builds.length; $('#statLicenses').textContent=licenses.filter(x=>x.status==='active').length; $('#statAudit').textContent=audit.length;
 $('#recentProjects').innerHTML=projects.slice(0,3).map(projectCard).join('')||empty('No projects yet. Create one to start your first build.');
}
function renderProjects(){ $('#projectsList').innerHTML=projects.map(projectCard).join('')||empty('No projects yet. Select “New project” to create one.'); }
function fillProjectSelect(){
 $('#buildProject').innerHTML='<option value="">Select a project</option>'+projects.map(p=>`<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('');
}
function renderBuilds(){
 $('#buildsTable').innerHTML=builds.length?`<table><thead><tr><th>FILE</th><th>PROJECT ID</th><th>SOURCE SHA-256</th><th>CREATED</th><th>STATUS</th><th></th></tr></thead><tbody>${builds.map(b=>`<tr><td>${esc(b.filename)}</td><td>${esc(b.project_id)}</td><td title="${esc(b.source_hash)}">${esc(b.source_hash.slice(0,16))}…</td><td>${new Date(b.created_at).toLocaleString()}</td><td><span class="badge">${esc(b.status)}</span></td><td><button class="small-btn" data-download="${esc(b.id)}">Download</button> <button class="small-btn danger" data-delete-build="${esc(b.id)}">Delete</button></td></tr>`).join('')}</tbody></table>`:empty('No builds have been generated yet.');
}
function renderLicenses(){
 $('#licensesTable').innerHTML=licenses.length?`<table><thead><tr><th>LABEL</th><th>KEY PREFIX</th><th>SCRIPT ID</th><th>STATUS</th><th>CREATED</th><th>ACTION</th></tr></thead><tbody>${licenses.map(l=>`<tr><td>${esc(l.label)}</td><td><code>${esc(l.prefix)}…</code></td><td>${esc(l.scriptId)}<br><small>${Number(l.activationCount||0)}/${Number(l.maxActivations||1)} devices</small></td><td><span class="badge ${l.status==='active'?'':'revoked'}">${esc(l.status)}</span></td><td>${new Date(l.createdAt).toLocaleDateString()}${l.expiresAt?`<br><small>Expires ${new Date(l.expiresAt).toLocaleDateString()}</small>`:''}</td><td><button class="small-btn" data-view-activations="${esc(l.id)}">Devices</button> ${l.status==='active'?`<button class="small-btn" data-edit-license="${esc(l.id)}">Edit</button> <button class="small-btn" data-reset-activations="${esc(l.id)}">Reset</button> <button class="small-btn danger" data-revoke="${esc(l.id)}">Revoke</button>`:'—'}</td></tr>`).join('')}</tbody></table>`:empty('No licenses yet. Create a key to control access.');
}
function renderAudit(){
 $('#auditTable').innerHTML=audit.length?`<table><thead><tr><th>EVENT</th><th>DETAIL</th><th>TIME</th></tr></thead><tbody>${audit.map(a=>`<tr><td>${esc(a.event)}</td><td>${esc(a.detail)}</td><td>${new Date(a.created_at).toLocaleString()}</td></tr>`).join('')}</tbody></table>`:empty('No audit events yet.');
}
async function enterApp(){ $('#login').classList.add('hidden'); $('#app').classList.remove('hidden'); await refresh(); }
$('#loginForm').addEventListener('submit',async e=>{e.preventDefault();$('#loginError').textContent='';try{await api('/login',{method:'POST',body:JSON.stringify({username:$('#username').value,password:$('#password').value})});await enterApp()}catch(err){$('#loginError').textContent=err.message}});
$('#logout').addEventListener('click',async()=>{try{await api('/logout',{method:'POST',body:'{}'})}finally{$('#app').classList.add('hidden');$('#login').classList.remove('hidden');$('#password').value=''}});
$$('[data-page]').forEach(b=>b.addEventListener('click',()=>showPage(b.dataset.page)));
$$('[data-go]').forEach(b=>b.addEventListener('click',()=>showPage(b.dataset.go)));
$('#menuToggle').addEventListener('click',()=>$('.sidebar').classList.toggle('open'));
$('#newProjectBtn').addEventListener('click',()=>$('#projectForm').classList.toggle('hidden'));
$('#projectForm').addEventListener('submit',async e=>{e.preventDefault();try{await api('/projects',{method:'POST',body:JSON.stringify({name:$('#projectName').value,description:$('#projectDescription').value})});e.target.reset();e.target.classList.add('hidden');await refresh();renderProjects();fillProjectSelect();notice('Project created.')}catch(err){notice(err.message,true)}});
$('#newLicenseBtn').addEventListener('click',()=>$('#licenseForm').classList.toggle('hidden'));
$('#licenseForm').addEventListener('submit',async e=>{e.preventDefault();try{const result=await api('/licenses/bulk',{method:'POST',body:JSON.stringify({label:$('#licenseLabel').value,scriptId:$('#licenseScript').value||'*',maxActivations:Number($('#licenseActivations').value||1),count:Number($('#licenseCount').value||1),expiresAt:$('#licenseExpiry').value?new Date($('#licenseExpiry').value+'T23:59:59Z').toISOString():null})});const keys=result.licenses.map(x=>x.key).join('\n');$('#newKeyBox').classList.remove('hidden');$('#newKeyBox').innerHTML=`<h3>${result.count} license key${result.count===1?'':'s'} created — copy now</h3><p class="muted">Complete keys are shown only once. Store them securely.</p><textarea id="newKeyValue" class="key-box" readonly rows="${Math.min(8,result.count)}">${esc(keys)}</textarea><div class="key-actions"><button id="copyKey" class="secondary">Copy all keys</button><button id="hideKey" class="small-btn">Hide keys</button></div>`;$('#copyKey').onclick=async()=>{try{await navigator.clipboard.writeText(keys);notice('Keys copied.')}catch{notice('Clipboard access failed. Select and copy the keys manually.',true)}};$('#hideKey').onclick=()=>$('#newKeyBox').classList.add('hidden');e.target.reset();$('#licenseActivations').value='1';$('#licenseCount').value='1';e.target.classList.add('hidden');await refresh();renderLicenses();notice('License keys created. Copy them before hiding this panel.')}catch(err){notice(err.message,true)}});
$('#sourceFile').addEventListener('change',async e=>{const f=e.target.files[0];if(!f)return;if(f.size>1_000_000){notice('File exceeds 1 MB limit.',true);e.target.value='';return}$('#source').value=await f.text();$('#sourceName').value=f.name;$('#fileName').textContent=f.name});
$('#buildForm').addEventListener('submit',async e=>{e.preventDefault();const projectId=$('#buildProject').value;if(!projectId)return notice('Create or select a project first.',true);const btn=e.submitter;btn.disabled=true;btn.textContent='Building…';try{const b=await api(`/projects/${encodeURIComponent(projectId)}/build`,{method:'POST',body:JSON.stringify({source:$('#source').value,name:$('#sourceName').value})});$('#buildResult').classList.remove('hidden');$('#buildResult').innerHTML=`<h3>Build completed</h3><p class="muted">Output: ${b.outputBytes} bytes · SHA-256: ${esc(b.sourceHash)}</p><p><span class="badge">${esc(b.status)}</span></p><p class="tiny muted">${esc(b.protectionNote)} ${esc(b.validation.note||'')}</p><button class="primary" data-download="${esc(b.id)}">Download build →</button>`;await refresh();notice('Build record created.')}catch(err){notice(err.message,true)}finally{btn.disabled=false;btn.innerHTML='Validate & build <span>→</span>'}});
document.addEventListener('click',async e=>{
 const build=e.target.closest('[data-build-for]'); if(build){$('#buildProject').value=build.dataset.buildFor;showPage('protect');$('#buildProject').value=build.dataset.buildFor;return}
 const edit=e.target.closest('[data-edit-project]');if(edit){const p=projects.find(x=>x.id===edit.dataset.editProject);if(!p)return;const name=prompt('Project name:',p.name);if(name===null)return;const description=prompt('Project description:',p.description||'');if(description===null)return;try{await api(`/projects/${encodeURIComponent(p.id)}`,{method:'PATCH',body:JSON.stringify({name,description})});await refresh();renderProjects();notice('Project updated.')}catch(err){notice(err.message,true)}return}
 const del=e.target.closest('[data-delete-project]');if(del){if(!confirm('Delete this project and its build records?'))return;try{await api(`/projects/${encodeURIComponent(del.dataset.deleteProject)}`,{method:'DELETE'});await refresh();renderProjects();fillProjectSelect();notice('Project deleted.')}catch(err){notice(err.message,true)}}
 const db=e.target.closest('[data-delete-build]');if(db){if(!confirm('Delete this build artifact permanently?'))return;try{await api(`/builds/${encodeURIComponent(db.dataset.deleteBuild)}`,{method:'DELETE'});await refresh();renderBuilds();notice('Build deleted.')}catch(err){notice(err.message,true)}return}
 const dl=e.target.closest('[data-download]');if(dl){window.location.href=`/api/builds/${encodeURIComponent(dl.dataset.download)}/download`;return}
 const editLicense=e.target.closest('[data-edit-license]');if(editLicense){const l=licenses.find(x=>x.id===editLicense.dataset.editLicense);if(!l)return;const label=prompt('License label:',l.label);if(label===null)return;const max=prompt('Maximum device activations (1–100):',String(l.maxActivations));if(max===null)return;const expiry=prompt('Expiry date/time in ISO format, or leave blank for no expiry:',l.expiresAt||'');if(expiry===null)return;try{await api(`/licenses/${encodeURIComponent(l.id)}`,{method:'PATCH',body:JSON.stringify({label,maxActivations:Number(max),expiresAt:expiry.trim()?new Date(expiry).toISOString():null})});await refresh();renderLicenses();notice('License updated.')}catch(err){notice(err.message,true)}return}
 const view=e.target.closest('[data-view-activations]');if(view){try{const rows=await api(`/licenses/${encodeURIComponent(view.dataset.viewActivations)}/activations`);if(!rows.length){notice('No devices activated for this license.');return}const details=rows.map((r,i)=>`${i+1}. ${r.id} — last seen ${new Date(r.last_seen_at).toLocaleString()}`).join('\n');const choice=prompt(`Activated devices (enter a row number to remove one):\n\n${details}\n\nCancel to close.`);if(choice===null||!choice.trim())return;const index=Number(choice)-1;if(!Number.isInteger(index)||index<0||index>=rows.length){notice('Invalid device number.',true);return}if(!confirm('Remove this device activation?'))return;await api(`/licenses/${encodeURIComponent(view.dataset.viewActivations)}/activations/${encodeURIComponent(rows[index].id)}`,{method:'DELETE'});await refresh();renderLicenses();notice('Device activation removed.')}catch(err){notice(err.message,true)}return}
 const reset=e.target.closest('[data-reset-activations]');if(reset){if(!confirm('Reset all device activations for this license?'))return;try{await api(`/licenses/${encodeURIComponent(reset.dataset.resetActivations)}/reset-activations`,{method:'POST',body:'{}'});await refresh();renderLicenses();notice('Device activations reset.')}catch(err){notice(err.message,true)}}
 const rev=e.target.closest('[data-revoke]');if(rev){if(!confirm('Revoke this license key?'))return;try{await api(`/licenses/${encodeURIComponent(rev.dataset.revoke)}/revoke`,{method:'POST',body:'{}'});await refresh();renderLicenses();notice('License revoked.')}catch(err){notice(err.message,true)}}
});
$('#refreshAudit').addEventListener('click',async()=>{try{audit=await api('/audit');renderAudit();notice('Audit log refreshed.')}catch(err){notice(err.message,true)}});
$('#checkHealth').addEventListener('click',async()=>{try{const h=await api('/health');notice(`${h.service} API is online · v${h.version}`)}catch(err){notice(err.message,true)}});
(async()=>{try{await api('/me');await enterApp()}catch{$('#login').classList.remove('hidden')}})();