const APPS_SCRIPT_URL = 'COLE_AQUI_A_URL_DO_WEB_APP';
const PIX_CHAVE = '[CHAVE_PIX]';

// [SEGURANÇA 1] Token estático — validação básica de origem
const SECURITY_TOKEN = 'PRIME_SECURE_2026';

// [SEGURANÇA HMAC] Secret de integridade (não de autenticação — exposto no frontend)
const HMAC_SECRET = 'COLE_AQUI_O_MESMO_SECRET_DO_APPS_SCRIPT';

// [SEGURANÇA CHALLENGE] Origem para vinculação do challenge
const ORIGIN_VALIDO = 'aflor_prime_council';

// [SEGURANÇA] Nonce aleatório forte: 32 hex chars (128 bits, CSPRNG)
function generateNonce() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2,'0')).join('');
}

// [SEGURANÇA HMAC] HMAC-SHA256 via SubtleCrypto nativo — sem libs externas
// Chaves ordenadas para garantir determinismo (backend faz o mesmo)
async function computeHMAC(message, secret) {
  const enc     = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// [SEGURANÇA CHALLENGE] Busca token efêmero no doGet antes do submit
// uaHash derivado via SHA-256 para alinhar com hashString() do backend
async function fetchChallenge() {
  try {
    const ua = navigator.userAgent.substring(0, 300);
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ua));
    const uaHash = Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('').substring(0,64);
    const url = APPS_SCRIPT_URL
      + '?action=challenge'
      + '&ua_hash=' + encodeURIComponent(uaHash)
      + '&origin='  + encodeURIComponent(ORIGIN_VALIDO);
    const resp = await fetch(url, { redirect: 'follow' });
    if (!resp.ok) return null;
    const json = await resp.json();
    return json.challenge_token || null;
  } catch (_) {
    return null;
  }
}

// [SEGURANÇA 3] Timestamp registrado no carregamento da página — bloqueia envio antes de 3s
const PAGE_LOAD_TS = Date.now();
const MIN_FILL_MS = 3000;

// [SEGURANÇA 4] Flag de controle de duplo submit
let isSubmitting = false;

let currentStep = 1;
let fileData = null;
let fileName = null;
let fileType = null;

function $(id){return document.getElementById(id)}

function setProgress(step){
  for(let i=1;i<=4;i++){
    const dot=$('dot'+i);
    const label=document.querySelectorAll('.step-label')[i-1];
    dot.className='step-dot'+(i<step?' done':i===step?' active':'');
    label.className='step-label'+(i<step?' done':i===step?' active':'');
    if(i<4){
      const line=$('line'+i);
      line.className='progress-line'+(i<step?' done':'');
    }
  }
}

function showStep(n){
  document.querySelectorAll('.step-panel').forEach(p=>p.classList.remove('active'));
  $('step'+n).classList.add('active');
  $('btnBack').style.visibility=n===1?'hidden':'visible';
  const btn=$('btnNext');
  if(n===4){
    btn.innerHTML='Concluir inscrição <div class="spinner" id="spinner"></div>';
    btn.className='btn-next gold';
  } else {
    btn.innerHTML='Próximo <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg><div class="spinner" id="spinner"></div>';
    btn.className='btn-next';
  }
  setProgress(n);
  window.scrollTo({top:0,behavior:'smooth'});
}

function validate(step){
  let ok=true;
  if(step===1){
    ok=req('nome','f-nome','Informe seu nome completo.')&&ok;
    ok=reqEmail('email','f-email')&&ok;
    ok=reqPhone('whatsapp','f-whatsapp')&&ok;
  }
  if(step===2){
    ok=req('empresa','f-empresa','Informe o nome da empresa.')&&ok;
    ok=req('cidade','f-cidade','Informe a cidade.')&&ok;
    ok=reqSel('estado','f-estado','Selecione o estado.')&&ok;
    ok=reqSel('cargo','f-cargo','Selecione sua posição.')&&ok;
    ok=reqSel('setor','f-setor','Selecione o setor.')&&ok;
  }
  if(step===3){
    ok=reqSel('colaboradores','f-colaboradores','Selecione o porte da equipe.')&&ok;
    ok=reqRadio('desafio','f-desafio','Selecione o principal desafio.')&&ok;
    ok=reqRadio('gestao','f-gestao','Selecione a estrutura de gestão.')&&ok;
    ok=reqSel('faturamento','f-faturamento','Selecione a faixa de faturamento.')&&ok;
  }
  if(step===4){
    if(!fileData){
      $('f-comprovante').classList.add('has-error');
      ok=false;
    }
    const cb=$('confirmacao');
    const cerr=$('confirm-err');
    if(!cb.checked){cerr.style.display='block';ok=false;}
    else{cerr.style.display='none';}
  }
  return ok;
}

function req(id,fid,msg){
  const el=$(id),f=$(fid);
  if(!el.value.trim()){
    f.classList.add('has-error');
    f.querySelector('.err-msg').textContent=msg;
    return false;
  }
  f.classList.remove('has-error');return true;
}
function reqEmail(id,fid){
  const el=$(id),f=$(fid);
  const ok=/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(el.value.trim());
  if(!ok){
    f.classList.add('has-error');
    const m=f.querySelector('.err-msg');
    if(m)m.textContent='Informe um e-mail válido.';
  }else{f.classList.remove('has-error');}
  return ok;
}
function reqPhone(id,fid){
  const el=$(id),f=$(fid);
  const digits=el.value.replace(/\D/g,'');
  const ok=digits.length===11 && digits[2]==='9';
  if(!ok){
    f.classList.add('has-error');
    const m=f.querySelector('.err-msg');
    if(m)m.textContent=digits.length!==11?'Informe um celular válido com DDD (11 dígitos).':'Informe um celular válido (com 9 após o DDD).';
  }else{f.classList.remove('has-error');}
  return ok;
}
function reqSel(id,fid,msg){
  const el=$(id),f=$(fid);
  if(!el.value){
    f.classList.add('has-error');
    if(f.querySelector('.err-msg'))f.querySelector('.err-msg').textContent=msg;
    return false;
  }
  f.classList.remove('has-error');return true;
}
function reqRadio(name,fid,msg){
  const checked=document.querySelector('input[name="'+name+'"]:checked');
  const f=$(fid);
  if(!checked){
    f.classList.add('has-error');
    f.querySelector('.err-msg').textContent=msg;
    return false;
  }
  f.classList.remove('has-error');return true;
}

function nextStep(){
  if(!validate(currentStep))return;
  if(currentStep<4){currentStep++;showStep(currentStep);}
  else{submitForm();}
}
function prevStep(){if(currentStep>1){currentStep--;showStep(currentStep);}}

document.querySelectorAll('.radio-opt').forEach(opt=>{
  opt.addEventListener('click',function(){
    const input=this.querySelector('input[type=radio]');
    const name=input.name;
    document.querySelectorAll('input[name="'+name+'"]').forEach(r=>{
      r.closest('.radio-opt').classList.remove('selected');
    });
    this.classList.add('selected');
    input.checked=true;
    const fid='f-'+name;
    if($(fid))$(fid).classList.remove('has-error');
  });
});

$('whatsapp').addEventListener('input',function(){
  let v=this.value.replace(/\D/g,'');
  if(v.length>11)v=v.slice(0,11);
  if(v.length>6)v='('+v.slice(0,2)+') '+v.slice(2,7)+'-'+v.slice(7);
  else if(v.length>2)v='('+v.slice(0,2)+') '+v.slice(2);
  else if(v.length>0)v='('+v;
  this.value=v;
});

function handleFile(input){
  const file=input.files[0];
  if(!file)return;
  if(file.size>5*1024*1024){alert('Arquivo muito grande. Limite: 5 MB.');input.value='';return;}
  fileName=file.name;fileType=file.type;
  const reader=new FileReader();
  reader.onload=function(e){
    fileData=e.target.result;
    $('uploadDefault').style.display='none';
    $('uploadPreview').classList.add('visible');
    $('uploadName').textContent=fileName;
    $('uploadBox').classList.add('has-file');
    $('f-comprovante').classList.remove('has-error');
  };
  reader.readAsDataURL(file);
}
function removeFile(e){
  e.preventDefault();e.stopPropagation();
  fileData=null;fileName=null;fileType=null;
  $('comprovante').value='';
  $('uploadDefault').style.display='block';
  $('uploadPreview').classList.remove('visible');
  $('uploadBox').classList.remove('has-file');
}

function copyPix(){
  navigator.clipboard.writeText(PIX_CHAVE).then(()=>{
    const btn=document.querySelector('.pix-copy-btn');
    btn.textContent='Copiado!';btn.classList.add('copied');
    setTimeout(()=>{btn.textContent='Copiar';btn.classList.remove('copied');},2000);
  });
}

// [SEGURANÇA 6] Sanitização básica: remove caracteres perigosos de strings antes do envio
function sanitize(str){
  if(typeof str !== 'string') return str;
  // [SEGURANÇA 8] Sanitização ampliada: remove tags HTML, protocolos perigosos e event handlers
  str = str.replace(/<[^>]*>/gi, '');            // tags HTML (<script>, <img>, etc)
  str = str.replace(/javascript\s*:/gi, '');     // protocolo javascript:
  str = str.replace(/data\s*:/gi, '');           // protocolo data:
  str = str.replace(/on\w+\s*=/gi, '');          // event handlers (onerror=, onclick=, etc)
  str = str.replace(/[<>{}"]/g, '');            // caracteres estruturais remanescentes
  return str.trim();
}

function getRadioVal(name){
  const c=document.querySelector('input[name="'+name+'"]:checked');
  if(!c)return '';
  return c.value;
}

function showFormError(msg){
  const el=$('form-err');
  if(!el)return;
  el.textContent=msg;
  el.style.display=msg?'block':'none';
}

async function submitForm(){
  // [SEGURANÇA 4] Bloqueia duplo submit
  if(isSubmitting) return;

  // [SEGURANÇA 2] Verifica honeypot — se preenchido, é bot; falha silenciosa
  const hp = document.getElementById('hp_website');
  if(hp && hp.value.length > 0) return;

  // [SEGURANÇA 3] Bloqueia envio se ocorrer antes de 3 segundos do carregamento
  if(Date.now() - PAGE_LOAD_TS < MIN_FILL_MS) return;

  // [SEGURANÇA 5] Validação mínima dos campos críticos antes de qualquer envio
  const nomeVal    = sanitize(document.getElementById('nome').value).trim();
  const emailVal   = document.getElementById('email').value.trim();
  const waVal      = document.getElementById('whatsapp').value.replace(/\D/g,'');
  const empresaVal = sanitize(document.getElementById('empresa').value).trim();
  if(!nomeVal || !empresaVal || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailVal) || waVal.length !== 11 || waVal[2] !== '9') return;

  // [SEGURANÇA 7] Whitelist dos SELECTs — rejeita valores adulterados via DevTools
  const WL = {
    estado:        ["AC","AL","AP","AM","BA","CE","DF","ES","GO","MA","MT","MS",
                    "MG","PA","PB","PR","PE","PI","RJ","RN","RS","RO","RR","SC","SP","SE","TO"],
    cargo:         ["Proprietário / Fundador","Sócio","CEO / Diretor Executivo","Diretor (área)","Outro"],
    setor:         ["Agronegócio","Construção Civil","Educação","Saúde","Indústria",
                    "Logística e Transporte","Serviços Profissionais","Tecnologia","Varejo e Comércio","Outro"],
    colaboradores: ["Até 50","51 a 100","101 a 200","Acima de 200"],
    faturamento:   ["Até R$ 1 milhão","R$ 1M a R$ 5M","R$ 5M a R$ 20M",
                    "R$ 20M a R$ 60M","Acima de R$ 60M","Prefiro não informar"],
  };
  const selChecks = ["estado","cargo","setor","colaboradores","faturamento"];
  for(const key of selChecks){
    const val = document.getElementById(key).value;
    if(val && !WL[key].includes(val)) return;
  }

  // TODO: integrar reCAPTCHA v3 aqui antes de prosseguir com o envio

  isSubmitting = true;
  showFormError('');

  const btn=$('btnNext');
  btn.disabled=true;
  const sp=document.createElement('div');sp.className='spinner visible';
  btn.innerHTML='Enviando... ';btn.appendChild(sp);

  // [SEGURANÇA] Fetch challenge efêmero antes de montar o payload
  const challengeToken = await fetchChallenge();
  if (!challengeToken) {
    isSubmitting = false;
    btn.disabled = false;
    btn.innerHTML = 'Concluir inscrição <div class="spinner" id="spinner"></div>';
    showFormError('Não foi possível conectar ao servidor. Verifique sua conexão e tente novamente.');
    return;
  }

  // [SEGURANÇA] Coleta de contexto para fingerprint e vinculação do challenge
  const userAgent = navigator.userAgent.substring(0, 300);
  const userTZ    = Intl.DateTimeFormat().resolvedOptions().timeZone || '';

  // [SEGURANÇA 6] sanitize() + campos de contexto e challenge
  const payloadBase = {
    _token:     SECURITY_TOKEN,
    _origin:    ORIGIN_VALIDO,
    _ts:        Date.now(),
    _nonce:     generateNonce(),
    _challenge: challengeToken,
    _ua:        userAgent,
    _tz:        userTZ,
    nome:       sanitize($('nome').value.trim()),
    email:      sanitize($('email').value.trim()),
    whatsapp:   waVal,
    empresa:    sanitize($('empresa').value.trim()),
    cidade:     sanitize($('cidade').value.trim()),
    estado:     $('estado').value,
    cargo:      $('cargo').value,
    setor:      $('setor').value,
    colaboradores: $('colaboradores').value,
    desafio:    getRadioVal('desafio'),
    gestao:     getRadioVal('gestao'),
    faturamento:$('faturamento').value,
    como_soube: $('como_soube').value||'',
    comprovante:      fileData,
    comprovante_nome: sanitize(fileName||''),
    comprovante_tipo: fileType,
  };

  // [SEGURANÇA HMAC] Ordena chaves e assina (integridade, não autenticação)
  const sortedKeys = Object.keys(payloadBase).sort();
  const sorted     = {};
  sortedKeys.forEach(k => sorted[k] = payloadBase[k]);
  const sig     = await computeHMAC(JSON.stringify(sorted), HMAC_SECRET);
  const payload = { ...payloadBase, signature: sig };

  try{
    const resp = await fetch(APPS_SCRIPT_URL,{
      method:'POST',
      headers:{'Content-Type':'text/plain','x-aflor-token':SECURITY_TOKEN},
      body:JSON.stringify(payload),
      redirect:'follow'
    });
    const result = await resp.json();
    if(!result.success) throw new Error('backend');
  }catch(_){
    isSubmitting = false;
    btn.disabled = false;
    btn.innerHTML = 'Concluir inscrição <div class="spinner" id="spinner"></div>';
    showFormError('Ocorreu um erro ao enviar a inscrição. Verifique sua conexão e tente novamente.');
    return;
  }

  $('mainCard').style.display='none';
  $('btnNav').style.display='none';
  $('successScreen').classList.add('visible');
  setProgress(5);
}