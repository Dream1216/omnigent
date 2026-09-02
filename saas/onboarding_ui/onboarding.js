(() => {
  "use strict";
  const app = document.querySelector("#app");
  const PENDING = "omnigent.saas.pending-registration";
  const CSRF = "omnigent.saas.csrf";
  const token = consumeToken();
  const path = location.pathname.replace(/\/$/, "") || "/";

  function consumeToken() {
    const params = new URLSearchParams(location.hash.slice(1));
    const value = params.get("token");
    if (location.hash) history.replaceState(history.state, "", location.pathname + location.search);
    return value && value.trim() ? value.trim() : null;
  }
  const esc = (value) => String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const uuid = (prefix) => `${prefix}-${crypto.randomUUID()}`;
  const pending = () => { try { return JSON.parse(sessionStorage.getItem(PENDING) || "null"); } catch { return null; } };
  const slug = value => value.toLowerCase().trim().replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"").slice(0,63);
  const returnTarget = value => { try { const target=new URL(value||"/",location.origin); return target.origin===location.origin&&target.pathname.startsWith("/")?target.pathname+target.search+target.hash:"/"; } catch { return "/"; } };
  const heading = (eyebrow,title,description,step=1) => `<p class="eyebrow">${esc(eyebrow)}</p><h1>${esc(title)}</h1><p class="lede">${esc(description)}</p><div class="steps"><b>0${step}</b><span style="--progress:${step*33}%"></span><em>${step} of 3</em></div>`;
  const errorText = error => error && error.message ? error.message : "The request could not be completed. Try again.";
  async function json(url, options={}) {
    let response;
    try { response = await fetch(url, {credentials:"same-origin", ...options}); }
    catch { throw new Error("Could not reach the server. Check your connection and try again."); }
    let payload = null; try { payload = await response.json(); } catch {}
    if (!response.ok) {
      if (response.status === 401) sessionStorage.removeItem(CSRF);
      const detail = payload && (payload.detail || payload.error);
      const message = detail && typeof detail.message === "string" ? detail.message : response.status >= 500 ? "The service is temporarily unavailable. Try again shortly." : "Check the submitted values and try again.";
      const retry = response.headers.get("Retry-After");
      throw new Error(retry ? `${message} Try again in ${retry} seconds.` : message);
    }
    if (!payload || typeof payload !== "object") throw new Error("The server returned an invalid response.");
    return payload;
  }
  const mutation = (body,key) => ({method:"POST",headers:{"content-type":"application/json","Idempotency-Key":key},body:JSON.stringify(body)});

  async function signup() {
    app.innerHTML = heading("Start your trial","Create your organization","Choose the workspace boundary, plan, and home region that your team will start with.",1) + '<p class="loading">Loading available plans and regions…</p>';
    let catalog; try { catalog = await json("/saas/onboarding/catalog", {cache:"no-cache"}); } catch (e) { app.innerHTML += `<div class="alert error">${esc(errorText(e))}</div>`; return; }
    const plans = catalog.plans.map((p,i)=>`<label class="plan"><input type="radio" name="plan" value="${esc(p.key)}" ${i===0?"checked":""}><strong>${esc(p.key[0].toUpperCase()+p.key.slice(1))}</strong><small>${p.trial_days} day trial · ${p.trial_run_limit.toLocaleString()} runs · ${p.trial_concurrency_limit} concurrent</small></label>`).join("");
    const regions = catalog.regions.map(r=>`<option value="${esc(r)}">${esc(r)}</option>`).join("");
    app.innerHTML = heading("Start your trial","Create your organization","Choose the workspace boundary, plan, and home region that your team will start with.",1)+`<form id="signup"><fieldset><legend>Your account</legend><div class="grid"><div class="field"><label for="email">Work email</label><input id="email" type="email" autocomplete="email" required autofocus></div><div class="field"><label for="display">Your name <span class="optional">optional</span></label><input id="display" autocomplete="name"></div></div></fieldset><fieldset><legend>Workspace</legend><div class="grid"><div class="field"><label for="tenant-name">Organization name</label><input id="tenant-name" required maxlength="256"></div><div class="field"><label for="tenant-slug">Organization URL</label><input id="tenant-slug" required pattern="[a-z0-9]+(?:-[a-z0-9]+)*"></div><div class="field"><label for="space-name">First space</label><input id="space-name" value="General" required></div><div class="field"><label for="space-slug">Space URL</label><input id="space-slug" value="general" required pattern="[a-z0-9]+(?:-[a-z0-9]+)*"></div></div></fieldset><fieldset><legend>Trial placement</legend><div class="plans">${plans}</div><div class="field"><label for="region">Home region</label><select id="region">${regions}</select></div></fieldset><div id="error"></div><button class="button full" type="submit">Continue →</button></form><p class="footer">Already have a workspace? <a href="/saas/login">Sign in</a></p>`;
    const form=app.querySelector("form"), tenant=app.querySelector("#tenant-name"), tenantSlug=app.querySelector("#tenant-slug"), space=app.querySelector("#space-name"), spaceSlug=app.querySelector("#space-slug");
    let tenantManual=false,spaceManual=false,key=null,fingerprint=null;
    tenant.addEventListener("input",()=>{if(!tenantManual)tenantSlug.value=slug(tenant.value)}); tenantSlug.addEventListener("input",()=>tenantManual=true);
    space.addEventListener("input",()=>{if(!spaceManual)spaceSlug.value=slug(space.value)}); spaceSlug.addEventListener("input",()=>spaceManual=true);
    form.addEventListener("submit",async e=>{e.preventDefault();const button=form.querySelector("button"),err=form.querySelector("#error");const body={email:form.email.value.trim().toLowerCase(),display_name:app.querySelector("#display").value.trim()||null,tenant_name:tenant.value.trim(),tenant_slug:tenantSlug.value.trim(),default_space_name:space.value.trim(),default_space_slug:spaceSlug.value.trim(),plan_key:new FormData(form).get("plan"),home_region:app.querySelector("#region").value};const next=JSON.stringify(body);if(next!==fingerprint){fingerprint=next;key=uuid("signup")}button.disabled=true;err.innerHTML="";try{const result=await json("/saas/onboarding/registrations",mutation(body,key));sessionStorage.setItem(PENDING,JSON.stringify({registrationId:result.registration_id,email:body.email,verifyKey:uuid("verify")}));location.assign(`/signup/verify?registration_id=${encodeURIComponent(result.registration_id)}`)}catch(cause){err.innerHTML=`<div class="alert error">${esc(errorText(cause))}</div>`;button.disabled=false}});
  }
  function registrationId(){return new URLSearchParams(location.search).get("registration_id") || pending()?.registrationId || ""}
  function verify() {
    const id=registrationId(), stored=pending(), saved=stored?.registrationId===id?stored:null; app.classList.add("compact");
    if(!id){app.innerHTML=heading("Verification","Open your registration link","The registration reference is missing. Start again to create a new workspace.",2)+'<a class="button full" href="/signup">Start again</a>';return}
    if(!token){app.innerHTML=heading("Check your inbox","Verify your work email","Use the secure link in the verification email. If it expired, request another one.",2)+`<form id="resend"><div class="field"><label for="email">Work email</label><input id="email" type="email" required value="${esc(saved?.email||"")}"></div><div id="error"></div><button class="button secondary full">Send another email</button></form>`;app.querySelector("form").addEventListener("submit",async e=>{e.preventDefault();const email=e.target.email.value.trim().toLowerCase();try{await json(`/saas/onboarding/registrations/${encodeURIComponent(id)}/resend`,mutation({email},uuid("resend")));sessionStorage.setItem(PENDING,JSON.stringify({registrationId:id,email,verifyKey:uuid("verify")}));app.querySelector("#error").innerHTML='<div class="alert">Verification email requested.</div>'}catch(c){app.querySelector("#error").innerHTML=`<div class="alert error">${esc(errorText(c))}</div>`}});return}
    app.innerHTML=heading("Email verified","Secure your account","Choose the password you will use to sign in to this organization.",2)+`<form id="verify"><div class="field"><label for="email">Work email</label><input id="email" type="email" required value="${esc(saved?.email||"")}"></div><div class="field"><label for="password">Password</label><input id="password" type="password" minlength="12" required></div><div class="field"><label for="confirm">Confirm password</label><input id="confirm" type="password" minlength="12" required></div><div id="error"></div><button class="button full">Verify and continue →</button></form>`;
    const verifyKey=saved?.registrationId===id&&saved.verifyKey?saved.verifyKey:uuid("verify");sessionStorage.setItem(PENDING,JSON.stringify({registrationId:id,email:saved?.email||"",verifyKey}));
    app.querySelector("form").addEventListener("submit",async e=>{e.preventDefault();const email=e.target.email.value.trim().toLowerCase(),password=e.target.password.value,err=app.querySelector("#error");if(password!==e.target.confirm.value){err.innerHTML='<div class="alert error">Passwords do not match.</div>';return}sessionStorage.setItem(PENDING,JSON.stringify({registrationId:id,email,verifyKey}));e.target.querySelector("button").disabled=true;try{await json(`/saas/onboarding/registrations/${encodeURIComponent(id)}/verify`,mutation({verification_token:token,password},verifyKey));const login=await json("/saas/auth/login",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({email,password})});sessionStorage.setItem(CSRF,login.csrf_token);sessionStorage.removeItem(PENDING);location.replace("/signup/status")}catch(c){err.innerHTML=`<div class="alert error">${esc(errorText(c))}</div>`;e.target.querySelector("button").disabled=false}});
  }
  async function status() {
    app.classList.add("compact");app.innerHTML=heading("Preparing workspace","Your workspace is taking shape","You can keep this page open. Each step comes from the provisioning service.",3)+'<p class="loading">Reading the latest setup state…</p>';
    try{const value=await json("/saas/onboarding/status",{cache:"no-store"});const complete=["ready_for_first_run","complete"].includes(value.state);const stages=["Billing and trial","Runtime placement","First project","Account activation","Ready for first run"];const active=Math.max(0,["billing","runtime","project","activation","first_run"].indexOf(value.stage));app.innerHTML=heading(complete?"Workspace ready":"Preparing workspace",complete?"Your organization is ready":"Your workspace is taking shape",complete?"The tenant boundary, first space, and runtime are ready for your first agent run.":"You can keep this page open. Each step comes from the provisioning service.",3)+`<ol class="progress">${stages.map((s,i)=>`<li class="${complete||i<active?"done":i===active?"active":""}">${esc(s)}</li>`).join("")}</ol>${complete?'<button class="button full" id="open">Open workspace →</button>':'<p class="footer">Setup is continuing safely…</p>'}`;app.querySelector("#open")?.addEventListener("click",()=>location.assign("/"));if(!complete&&["provisioning","recovering"].includes(value.state))setTimeout(status,2000)}catch(c){app.innerHTML=heading("Setup status","Sign in to continue","We could not read the workspace setup state.",3)+`<div class="alert error">${esc(errorText(c))}</div><a class="button full" href="/saas/login?return_to=%2Fsignup%2Fstatus">Sign in to continue</a>`}
  }
  function login(){app.classList.add("compact");const params=new URLSearchParams(location.search);app.innerHTML=heading("Welcome back","Sign in to your workspace","Use your Omnigent account to continue.",1)+`<form id="login"><div class="field"><label for="email">Work email</label><input id="email" type="email" required autocomplete="email" value="${esc(params.get("email")||"")}"></div><div class="field"><label for="password">Password</label><input id="password" type="password" required autocomplete="current-password"></div><div id="error"></div><button class="button full">Sign in</button></form><p class="footer">New to Omnigent? <a href="/signup">Create a workspace</a></p>`;app.querySelector("form").addEventListener("submit",async e=>{e.preventDefault();try{const value=await json("/saas/auth/login",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({email:e.target.email.value.trim().toLowerCase(),password:e.target.password.value})});sessionStorage.setItem(CSRF,value.csrf_token);location.assign(returnTarget(params.get("return_to")))}catch(c){app.querySelector("#error").innerHTML=`<div class="alert error">${esc(errorText(c))}</div>`}})}
  if(path==="/signup") signup(); else if(path==="/signup/verify") verify(); else if(path==="/signup/status") status(); else login();
})();
