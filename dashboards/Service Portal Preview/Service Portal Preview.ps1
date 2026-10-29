#Requires -Version 7.0

# Authenticated visual proof of concept. No PSU API calls or backend jobs.
$page = New-UDPage -Name 'Home' -Url '/' -DefaultHomePage -Blank -Content {
    $document = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>ArchiTech Labs Service Portal Preview</title>
<style>:root{color-scheme:light dark}html,body{margin:0;padding:0}body{padding-bottom:24px}button{cursor:pointer}</style>
</head>
<body>
<style>
#service-portal-concept .portal-product{--p-bg:light-dark(#f4f7fa,#171d25);--p-surface:light-dark(#fff,#202833);--p-text:light-dark(#1a2c3e,#e8eef5);--p-muted:light-dark(#536478,#abb9ca);--p-border:light-dark(#dbe3ec,#3d4b5d);--p-accent:light-dark(#165fba,#8ec3ff);--p-soft:light-dark(#eaf3ff,#263c56);--p-chrome:light-dark(#152c42,#111d2c);--p-warning:light-dark(#fff7df,#3d3320);--p-warning-text:light-dark(#694800,#ffe2a0);font:14px/1.5 system-ui,sans-serif;color:var(--p-text);background:var(--p-bg);min-height:100vh;border:0;border-radius:0;overflow:hidden}
#service-portal-concept .portal-product *{box-sizing:border-box}
#service-portal-concept .portal-product [hidden]{display:none!important}
#service-portal-concept .portal-product button,#service-portal-concept .portal-product input,#service-portal-concept .portal-product select{font:inherit}
#service-portal-concept .portal-top{display:flex;align-items:center;gap:12px;padding:18px 24px;background:var(--p-chrome);color:#fff;min-height:74px}
#service-portal-concept .portal-mark{display:grid;place-items:center;flex-shrink:0;width:36px;height:36px;border:1px solid #8ea5bc;border-radius:8px;font-weight:500}
#service-portal-concept .portal-brand{font-weight:500;letter-spacing:.01em}
#service-portal-concept .portal-subbrand{color:#c9d8e7;font-size:12px}
#service-portal-concept .portal-mode{margin-left:auto;margin-right:0;color:#d5e4f4;font-size:12px;white-space:nowrap}
#service-portal-concept .portal-shell{display:grid;grid-template-columns:182px minmax(0,1fr);min-height:calc(100vh - 74px)}
#service-portal-concept .portal-nav{padding:24px 12px;background:var(--p-surface);border-right:1px solid var(--p-border)}
#service-portal-concept .portal-nav-label{font-size:11px;letter-spacing:.09em;color:var(--p-muted);margin:0 12px 12px}
#service-portal-concept .portal-nav button{display:flex;align-items:center;gap:10px;width:100%;text-align:left;padding:11px 12px;border:0;background:transparent;color:var(--p-muted);border-radius:6px;margin-bottom:5px}
#service-portal-concept .portal-nav button[aria-pressed=true]{background:var(--p-soft);color:var(--p-accent);font-weight:500}
#service-portal-concept .portal-nav .portal-count{margin-left:auto;font-size:12px;font-variant-numeric:tabular-nums}
#service-portal-concept .portal-nav hr{border:0;border-top:1px solid var(--p-border);margin:20px 10px}
#service-portal-concept .portal-main{min-width:0;padding:26px}
#service-portal-concept .portal-path{font-size:12px;color:var(--p-muted);margin-bottom:12px}
#service-portal-concept h1{font-size:27px;line-height:1.2;font-weight:500;margin:0 0 10px;letter-spacing:-.02em}
#service-portal-concept h2{font-size:18px;line-height:1.35;font-weight:500;margin:0}
#service-portal-concept h3{font-size:15px;font-weight:500;margin:0 0 12px}
#service-portal-concept p{margin:0 0 16px}
#service-portal-concept .portal-muted{color:var(--p-muted)}
#service-portal-concept .portal-toolbar{display:flex;gap:10px;align-items:end;margin:24px 0 16px}
#service-portal-concept .portal-search{display:flex;align-items:center;gap:9px;flex:1;min-width:0;padding:10px 12px;border:1px solid var(--p-border);background:var(--p-surface);border-radius:7px}
#service-portal-concept .portal-search input{border:0;background:transparent;color:var(--p-text);width:100%;min-width:0;outline-offset:4px}
#service-portal-concept .portal-types{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px}
#service-portal-concept .portal-filter{padding:7px 12px;border:1px solid var(--p-border);background:var(--p-surface);color:var(--p-muted);border-radius:6px}
#service-portal-concept .portal-filter[aria-pressed=true]{border-color:var(--p-accent);background:var(--p-soft);color:var(--p-accent)}
#service-portal-concept .portal-result-count{font-size:12px;margin:0 0 12px;color:var(--p-muted)}
#service-portal-concept .portal-resources{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--portal-spacing,16px)}
#service-portal-concept .portal-resource{display:flex;flex-direction:column;min-width:0;background:var(--p-surface);border:1px solid var(--p-border);border-radius:9px;padding:20px;gap:13px}
#service-portal-concept .portal-resource p{margin:0;color:var(--p-muted);font-size:13px}
#service-portal-concept .portal-resource-head{display:flex;justify-content:space-between;align-items:center;gap:8px}
#service-portal-concept .portal-resource-icon{color:var(--p-accent);display:flex;align-items:center}
#service-portal-concept .portal-type{font-size:11px;padding:3px 8px;background:var(--p-soft);color:var(--p-accent);border-radius:4px;white-space:nowrap}
#service-portal-concept .portal-system{font-size:12px;color:var(--p-muted)}
#service-portal-concept .portal-resource-foot{display:flex;align-items:center;gap:10px;justify-content:space-between;margin-top:auto;padding-top:5px}
#service-portal-concept .portal-action{display:inline-flex;align-items:center;justify-content:center;gap:7px;background:var(--p-accent);color:light-dark(#fff,#102238);border:1px solid transparent;border-radius:6px;padding:9px 14px;font-weight:500;white-space:nowrap}
#service-portal-concept .portal-action.secondary{background:var(--p-surface);color:var(--p-text);border-color:var(--p-border)}
#service-portal-concept .portal-back{display:inline-flex;gap:7px;align-items:center;border:0;padding:0;background:transparent;color:var(--p-accent);margin-bottom:18px}
#service-portal-concept .portal-footnote{font-size:12px;color:var(--p-muted);margin-top:24px;padding-top:16px;border-top:1px solid var(--p-border)}
#service-portal-concept .portal-notice{display:flex;align-items:start;gap:9px;padding:12px 14px;margin:18px 0;border:1px solid var(--p-border);border-radius:7px;background:var(--p-soft);font-size:13px}
#service-portal-concept .portal-detail{background:var(--p-surface);border:1px solid var(--p-border);border-radius:9px;padding:22px;margin-top:20px;min-width:0}
#service-portal-concept .portal-detail h2{margin-bottom:18px}
#service-portal-concept .portal-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;margin:0 0 20px}
#service-portal-concept .portal-field{display:flex;flex-direction:column;gap:7px;min-width:0}
#service-portal-concept .portal-field.wide{grid-column:1/-1}
#service-portal-concept .portal-field label{font-size:13px;font-weight:500}
#service-portal-concept .portal-field input,#service-portal-concept .portal-field select{width:100%;padding:10px;border:1px solid var(--p-border);border-radius:6px;background:var(--p-bg);color:var(--p-text);min-width:0}
#service-portal-concept .portal-field small{color:var(--p-muted);font-size:12px}
#service-portal-concept .portal-check{display:flex;align-items:center;gap:8px;grid-column:1/-1;font-size:13px}
#service-portal-concept .portal-result{margin-top:24px;min-width:0}
#service-portal-concept .portal-result pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--p-bg);color:var(--p-text);padding:16px;border-radius:6px;font:12px/1.6 ui-monospace,monospace;margin:12px 0}
#service-portal-concept .portal-table{width:100%;border-collapse:collapse;table-layout:fixed;font-size:12px}
#service-portal-concept .portal-table th{text-align:left;font-weight:500;color:var(--p-muted);background:var(--p-bg)}
#service-portal-concept .portal-table th,#service-portal-concept .portal-table td{padding:12px 8px;overflow-wrap:anywhere;border-bottom:1px solid var(--p-border);vertical-align:top}
#service-portal-concept .portal-badge{display:inline-block;font-size:11px;padding:3px 7px;border:1px solid var(--p-border);border-radius:4px;color:var(--p-muted);margin-bottom:12px}
#service-portal-concept .portal-banner{border:2px solid light-dark(#b67c14,#cfa247);color:var(--p-warning-text);background:var(--p-warning);padding:14px;font-size:13px;line-height:1.6;margin:14px 0 20px}
#service-portal-concept .portal-banner strong{font-weight:500}
#service-portal-concept .portal-empty{padding:32px 16px;text-align:center;color:var(--p-muted);border:1px dashed var(--p-border);border-radius:8px}
#service-portal-concept .portal-group-title{grid-column:1/-1;color:var(--p-muted);font-size:12px;letter-spacing:.06em;margin:12px 0 0;text-transform:uppercase}
#service-portal-concept [data-layout=list] .portal-resources{grid-template-columns:minmax(0,1fr);gap:10px}
#service-portal-concept [data-layout=list] .portal-resource{display:grid;grid-template-columns:32px minmax(0,1fr) auto;gap:14px;align-items:center;padding:17px 18px}
#service-portal-concept [data-layout=list] .portal-resource-head{display:contents}
#service-portal-concept [data-layout=list] .portal-resource-head .portal-type{display:none}
#service-portal-concept [data-layout=list] .portal-resource-foot{display:contents}
#service-portal-concept [data-layout=list] .portal-resource-foot .portal-system{display:none}
#service-portal-concept [data-layout=list] .portal-resource-copy h3{font-size:16px;margin-bottom:5px}
#service-portal-concept .portal-product button:focus-visible,#service-portal-concept .portal-product input:focus-visible,#service-portal-concept .portal-product select:focus-visible{outline:2px solid var(--p-accent);outline-offset:3px}
@media(max-width:760px){#service-portal-concept .portal-shell{grid-template-columns:145px minmax(0,1fr)}#service-portal-concept .portal-main{padding:20px}#service-portal-concept .portal-resources{grid-template-columns:minmax(0,1fr)}#service-portal-concept .portal-nav{padding:22px 8px}#service-portal-concept .portal-mode{margin-right:65px}#service-portal-concept .portal-fields{grid-template-columns:minmax(0,1fr)}}
@media(max-width:520px){#service-portal-concept .portal-shell{display:block}#service-portal-concept .portal-nav{display:flex;flex-wrap:wrap;gap:5px;padding:12px;border-right:0;border-bottom:1px solid var(--p-border)}#service-portal-concept .portal-nav button{width:auto;margin:0;padding:9px 11px}#service-portal-concept .portal-nav-label,#service-portal-concept .portal-nav hr,#service-portal-concept .portal-count{display:none}#service-portal-concept .portal-main{padding:18px}#service-portal-concept .portal-top{padding:16px}#service-portal-concept .portal-mode{display:none}#service-portal-concept h1{font-size:24px}#service-portal-concept .portal-resource{padding:17px}#service-portal-concept .portal-detail{padding:16px}#service-portal-concept [data-layout=list] .portal-resource{grid-template-columns:minmax(0,1fr);gap:10px}#service-portal-concept [data-layout=list] .portal-resource-icon{display:none}#service-portal-concept [data-layout=list] .portal-resource-foot{display:flex;justify-content:flex-start}#service-portal-concept .portal-product{min-height:1100px}}
@media(pointer:coarse){#service-portal-concept .portal-product button{min-height:44px}#service-portal-concept .portal-product input,#service-portal-concept .portal-product select{font-size:16px}}
#service-portal-concept .portal-symbol{display:inline-flex;align-items:center;justify-content:center;min-width:17px;font-size:18px;line-height:1}
</style>
<div id="service-portal-concept" aria-label="Service Portal preview">
  <section data-variant="Cards" aria-label="Cards catalog design"><div class="portal-product" data-layout="cards"></div></section>
</div>
<template id="service-portal-shell">
  <header class="portal-top"><div class="portal-mark" aria-hidden="true">AL</div><div><div class="portal-brand">ArchiTech Labs</div><div class="portal-subbrand">Service Portal</div></div><span class="portal-mode">Preview only</span></header>
  <div class="portal-shell">
    <nav class="portal-nav" aria-label="Service Portal navigation">
      <div class="portal-nav-label">SYSTEMS</div>
      <button type="button" data-system="All systems" aria-pressed="true"><i data-lucide="layout-grid" aria-hidden="true"></i>All services<span class="portal-count">4</span></button>
      <button type="button" data-system="Entra ID" aria-pressed="false"><i data-lucide="shield-check" aria-hidden="true"></i>Entra ID<span class="portal-count">2</span></button>
      <button type="button" data-system="Exchange Online" aria-pressed="false"><i data-lucide="mail" aria-hidden="true"></i>Exchange Online<span class="portal-count">3</span></button>
      <hr>
      <button type="button" data-history aria-pressed="false"><i data-lucide="history" aria-hidden="true"></i>History</button>
    </nav>
    <main class="portal-main"></main>
  </div>
</template>
<script>
(() => {
  const root = document.getElementById('service-portal-concept');
  const shell = document.getElementById('service-portal-shell');
  const resources = [
    {id:'ca',title:'Conditional Access policy report',type:'Reports',systems:['Entra ID'],icon:'shield-check',description:'Review policy states and explore the filters for a Conditional Access CSV export.',file:'Export-EntraCAPoliciesReport.ps1',action:'Open report'},
    {id:'transport',title:'External email disclaimer rule',type:'Scripts',systems:['Exchange Online'],icon:'mail',description:'Configure the organization prefix, priority, and proposed state of an inbound banner rule.',file:'New-EXOExternalDisclaimerTransportRule.ps1',action:'Open form'},
    {id:'banner',title:'External email banner preview',type:'Apps',systems:['Exchange Online'],icon:'panel-top',description:'See how the external sender warning appears above an example email.',file:'External Email Banner POC',action:'Preview banner'},
    {id:'demo',title:'Service Portal sample report',type:'Reports',systems:['Entra ID','Exchange Online'],icon:'table-properties',description:'Explore a report table backed by a small PowerShell script and sample data.',file:'Get-ServicePortalDemoReport.ps1',action:'Open report'}
  ];
  const sampleRows = [
    {system:'Entra ID',service:'Require multifactor authentication',state:'Enabled'},
    {system:'Entra ID',service:'Block legacy authentication',state:'Report only'},
    {system:'Exchange Online',service:'Inbound external email banner',state:'Disabled'}
  ];
  const views=[];
  const esc = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const symbols = {"layout-grid": "▦", "shield-check": "◇", "mail": "✉", "history": "◷", "panel-top": "▣", "table-properties": "▤", "info": "ⓘ", "search": "⌕", "arrow-up-right": "↗", "arrow-left": "←"};
  const icon = name => `<span class="portal-symbol" aria-hidden="true">${symbols[name] || ""}</span>`;
  const icons = () => root.querySelectorAll("[data-lucide]").forEach(element => { element.className="portal-symbol"; element.textContent=symbols[element.dataset.lucide] || ""; });
  const footer = '<div class="portal-footnote">Preview only · Sample data · No scripts are executed</div>';
  const notice = '<div class="portal-notice">'+icon('info')+'<span>Preview mode. Forms and results use sample data; no tenant connection or live script execution.</span></div>';
  function serviceCard(item) {
    return `<article class="portal-resource"><div class="portal-resource-head"><span class="portal-resource-icon">${icon(item.icon)}</span><span class="portal-type">${item.type.slice(0,-1)}</span></div><div class="portal-resource-copy"><h2>${item.title}</h2><p>${item.description}</p></div><div class="portal-resource-foot"><span class="portal-system">${item.systems.join(' + ')}</span><button type="button" class="portal-action secondary" data-open="${item.id}">${item.action}${icon('arrow-up-right')}</button></div></article>`;
  }
  function visibleResources(view) {return resources.filter(item=>(view.system==='All systems'||item.systems.includes(view.system))&&(view.type==='All'||item.type===view.type)&&(!view.query||[item.title,item.description,...item.systems,item.type].join(' ').toLowerCase().includes(view.query.toLowerCase())));}
  function updateList(view) {
    const items=visibleResources(view);
    const target=view.main.querySelector('[data-resources]');
    if(!target)return;
    if(view.layout==='list'){
      const groups=['Entra ID','Exchange Online','Across systems'];
      target.innerHTML=groups.map(group=>{const matches=items.filter(item=>(item.systems.length>1?'Across systems':item.systems[0])===group);return matches.length?`<h2 class="portal-group-title">${group}</h2>`+matches.map(item=>serviceCard(item).replace('<h2>','<h3>').replace('</h2>','</h3>')).join(''):'';}).join('');
    } else target.innerHTML=items.map(serviceCard).join('');
    if(!items.length)target.innerHTML='<div class="portal-empty">No services match your search.</div>';
    view.main.querySelector('[data-result-count]').textContent=`${items.length} service${items.length===1?'':'s'}`;
    icons();
  }
  function catalog(view){
    view.main.innerHTML=`<div class="portal-path">Services / ${esc(view.system)}</div><h1>${view.system==='All systems'?'Your service catalog':esc(view.system)}</h1><p class="portal-muted">Find a tool, review its options, and explore its results.</p><div class="portal-toolbar"><label class="portal-search">${icon('search')}<input data-search type="search" aria-label="Search services" placeholder="Search scripts, reports, and apps" value="${esc(view.query)}"></label></div><div class="portal-types" aria-label="Resource types">${['All','Scripts','Reports','Apps'].map(t=>`<button type="button" class="portal-filter" data-type="${t}" aria-pressed="${view.type===t}">${t}</button>`).join('')}</div><p class="portal-result-count" data-result-count role="status" aria-live="polite"></p><div class="portal-resources" data-resources></div>${footer}`;
    view.main.querySelector('[data-search]').addEventListener('input',event=>{view.query=event.target.value;updateList(view);});
    updateList(view);
  }
  function table(rows){return `<span class="portal-badge">Sample data</span><table class="portal-table"><caption style="text-align:left;margin-bottom:12px">Example service configuration</caption><thead><tr><th scope="col">System</th><th scope="col">Service / policy</th><th scope="col">Example state</th></tr></thead><tbody>${rows.map(row=>`<tr><td>${row.system}</td><td>${row.service}</td><td>${row.state}</td></tr>`).join('')}</tbody></table>`;}
  function record(view,item){view.runs.unshift({id:item.id,title:item.title});view.runs=view.runs.slice(0,6);}
  function showBanner(target,org='Contoso Corp'){
    target.innerHTML=`<h2>Email preview</h2><p class="portal-muted">From: Example sender &lt;sender@example.net&gt;<br>Subject: Document for your review</p><div class="portal-banner" role="note" aria-label="External email warning"><strong>⚠ External Email – Verify Before You Act ⚠</strong><br><br>This email is from <strong>outside the organization</strong>.<br>• Do not reply, click links, or open attachments unless you trust the sender.<br>• If it appears to be from someone inside the organization, confirm via another method before taking action.<br>• Report suspicious messages using the <strong>Report</strong> button.</div><p>Hello,<br>Please review the document when you have a moment.</p><p class="portal-muted">Processing header: ${esc('X-'+org.replace(/\s/g,'')+'-Disclaimer-External')}</p>`;
  }
  function details(view,item){
    view.main.innerHTML=`<button type="button" class="portal-back" data-back>${icon('arrow-left')}Back to services</button><div class="portal-path">${item.systems.join(' + ')} / ${item.type}</div><h1>${item.title}</h1><p class="portal-muted">${item.description}</p>${notice}<section class="portal-detail"><div data-detail-content></div></section>${footer}`;
    const content=view.main.querySelector('[data-detail-content]');
    if(item.id==='banner'){
      showBanner(content);
      content.insertAdjacentHTML('beforeend','<p class="portal-muted">This specialized preview can sit alongside scripts and reports in the same catalog.</p>');
    }else if(item.id==='transport'){
      content.innerHTML=`<h2>Rule parameters</h2><form data-demo-form><div class="portal-fields"><div class="portal-field"><label>Organization prefix<input name="org" value="Contoso Corp" required minlength="2" maxlength="50" pattern="[A-Za-z0-9 ]+" autocomplete="off"></label></div><div class="portal-field"><label>Priority<input name="priority" type="number" min="0" max="100" step="1" value="0" required></label></div><div class="portal-field wide"><label>Rule name<input name="rule" value="Security – Inbound External – Prepend Disclaimer" required></label></div><label class="portal-check"><input name="disabled" type="checkbox" checked>Propose creating the rule disabled</label></div><button class="portal-action" type="button" data-preview-submit>Preview configuration</button></form><div class="portal-result" data-result role="status" aria-live="polite"></div>`;
      content.querySelector('[data-preview-submit]').addEventListener('click',event=>{
        event.preventDefault();const form=event.currentTarget.closest('form');if(!form.reportValidity())return;const org=form.elements.org.value.trim();const result=content.querySelector('[data-result]');
        if(org.replace(/\s/g,'').length<2){result.textContent='Enter at least two letters or numbers in the organization prefix.';return;}
        const quoted=value=>value.replace(/['‘’‚‛]/g,c=>c+c);
        const command=`& './ExchangeOnline/New-EXOExternalDisclaimerTransportRule.ps1' -OrgPrefix '${quoted(org)}' -Priority ${Number(form.elements.priority.value)} -RuleName '${quoted(form.elements.rule.value)}'${form.elements.disabled.checked?' -Disabled':''} -WhatIf`;
        result.innerHTML='<span class="portal-badge">Simulated preview</span><h3>Command for review</h3><pre></pre><p class="portal-muted">The command is shown as text and has not been run.</p>';
        result.querySelector('pre').textContent=command;record(view,item);
      });
    }else{
      const isCA=item.id==='ca';
      content.innerHTML=`<h2>Report options</h2><form data-demo-form><div class="portal-fields"><div class="portal-field wide"><label>${isCA?'Policy state':'System'}<select name="filter">${(isCA?['All states','Enabled','Report only','Disabled']:['All systems','Entra ID','Exchange Online']).map(option=>`<option>${option}</option>`).join('')}</select></label><small>${isCA?'The repository exporter produces a CSV; this concept shows a possible future report view.':'These sample rows show how a script-backed report could appear.'}</small></div></div><button class="portal-action" type="button" data-preview-submit>Generate sample report</button></form><div class="portal-result" data-result role="status" aria-live="polite"></div>`;
      content.querySelector('[data-preview-submit]').addEventListener('click',event=>{event.preventDefault();const value=event.currentTarget.closest('form').elements.filter.value;const rows=sampleRows.filter(row=>isCA?(row.system==='Entra ID'&&(value==='All states'||row.state===value)):(value==='All systems'||row.system===value));const result=content.querySelector('[data-result]');result.innerHTML=rows.length?table(rows):'<div class="portal-empty">No sample rows match this filter.</div>';record(view,item);});
    }
    icons();view.main.querySelector('[data-back]').focus();
  }
  function history(view){
    view.main.innerHTML=`<div class="portal-path">Services / History</div><h1>Activity history</h1><p class="portal-muted">Previews generated during this demonstration.</p><section class="portal-detail">${view.runs.length?'<span class="portal-badge">Simulated activity</span><table class="portal-table"><thead><tr><th scope="col">Service</th><th scope="col">Result</th></tr></thead><tbody>'+view.runs.map(run=>`<tr><td>${run.title}</td><td>Preview generated</td></tr>`).join('')+'</tbody></table>':'<div class="portal-empty">No previews generated yet. Open a script or report to explore the workflow.</div>'}</section>${footer}`;
  }
  function render(view){
    view.product.querySelectorAll('[data-system]').forEach(button=>button.setAttribute('aria-pressed',String(!view.history&&button.dataset.system===view.system)));
    view.product.querySelector('[data-history]').setAttribute('aria-pressed',String(view.history));
    if(view.history)history(view);else if(view.selected)details(view,resources.find(item=>item.id===view.selected));else catalog(view);
  }
  root.querySelectorAll('.portal-product').forEach(product=>{
    product.append(shell.content.cloneNode(true));
    const view={product,main:product.querySelector('main'),layout:product.dataset.layout,system:'All systems',type:'All',query:'',selected:null,history:false,runs:[]};views.push(view);
    product.addEventListener('click',event=>{
      const button=event.target.closest('button');if(!button)return;
      if(button.hasAttribute('data-system')){view.system=button.dataset.system;view.selected=null;view.history=false;render(view);}
      else if(button.hasAttribute('data-history')){view.history=true;view.selected=null;render(view);}
      else if(button.hasAttribute('data-type')){view.type=button.dataset.type;catalog(view);}
      else if(button.hasAttribute('data-open')){view.selected=button.dataset.open;details(view,resources.find(item=>item.id===view.selected));}
      else if(button.hasAttribute('data-back')){view.selected=null;render(view);}
    });
  });
  views.forEach(render);
  icons();
})();
</script>

</body>
</html>
'@
    New-UDElement -Tag 'iframe' -Id 'service-portal-preview' -Attributes @{
        title = 'ArchiTech Labs Service Portal preview'
        srcDoc = $document
        sandbox = 'allow-scripts'
        referrerPolicy = 'no-referrer'
        style = @{ position = 'fixed'; inset = 0; width = '100%'; height = '100%'; border = 0 }
    }
}

New-UDApp -Title 'ArchiTech Labs Service Portal' -Pages @($page)
