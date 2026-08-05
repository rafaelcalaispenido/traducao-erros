/* ================= TOKEN CRIPTOGRAFADO (AES-GCM + PBKDF2) ================= */
const _ENC = {
  salt: "5355287455026cabf1801ebad327b06c",
  iv:   "b536e19fab9fe1426a15b1cb",
  data: "f4ff9b6ac4d473b402c2330144e0766b337c8a77dbdcdd3162a79037a1976ab07b732655390ff8de8ea5968438694df8b39af84fcbaf95bf"
};
let _token = null;
const getToken = () => _token;

function fromHex(hex){ return new Uint8Array(hex.match(/.{2}/g).map(b=>parseInt(b,16))); }

async function decryptToken(password){
  const keyMaterial = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name:"PBKDF2", salt:fromHex(_ENC.salt), iterations:100000, hash:"SHA-256" },
    keyMaterial, { name:"AES-GCM", length:256 }, false, ["decrypt"]
  );
  const decrypted = await crypto.subtle.decrypt({ name:"AES-GCM", iv:fromHex(_ENC.iv) }, key, fromHex(_ENC.data));
  return new TextDecoder().decode(decrypted);
}

const GIST_ID = "021dfd6c019adda202dd94d04dc34a5b";
const GIST_FILE = "nfse-errors.json";
const GIST_API = `https://api.github.com/gists/${GIST_ID}`;

/* ================= SEED DE ERROS ================= */
const SEED_RAW = {
  portal_nacional: [
    ["E0010","A série informada na DPS não pertence à faixa definida para o tipo de emissor"],
    ["E0014","O número do RPS/DPS informado já foi utilizado em outra NFS-e emitida no Emissor Nacional"],
    ["E0025","A data de competência informada na DPS deve ser igual ou posterior à data de autorização registrada no CNC"],
    ["E0032","Os dados cadastrais da empresa não foram informados corretamente"],
    ["E0038","A situação do convênio do município emissor deve ser ATIVO no cadastro de convênio municipal"],
    ["E0060","Situação da nota: Tributado Prestador (TP)"],
    ["E0061","Situação da nota: Tributado Tomador (TT)"],
    ["E0081","Alíquota do Simples Nacional não definida nesta competência"],
    ["E0093","O município emissor deve estar parametrizado para utilizar emissores públicos nacionais"],
    ["E0116","A Inscrição Municipal do emitente deve ser informada conforme informações complementares registradas no CNC"],
    ["E0120","No Padrão Nacional a IM do prestador não deve ser informada quando não há informações complementares no CNC"],
    ["E0160","O regime de tributação Simples Nacional configurado difere do cadastro do Simples Nacional"],
    ["E0240","O CEP informado para o endereço do tomador não existe ou não pertence ao município informado"],
    ["E0304","O Código Complementar Municipal não foi preenchido ou está preenchido incorretamente"],
    ["E0310","O código de tributação nacional informado não existe conforme a lista de serviços nacional"],
    ["E0312","O código de tributação nacional não está administrado pelo município de incidência do ISSQN na data de competência"],
    ["E0370","O grupo de informações de obra é obrigatório para os subitens de serviço listados"],
    ["E0713","Para Não Optante: o indicador de valor total de tributos e percentual do Simples não podem ser informados"],
    ["E1010","A partir de 01/10/2025 empresas Sociedade de Profissionais estão obrigadas a emitir no Padrão Nacional"],
    ["E1011","A partir de 01/11/2025 empresas do Simples Nacional estão obrigadas a emitir no Padrão Nacional"],
    ["GW3000","Código de tributação informado é inválido"],
    ["L64","A partir de 01/10/2023 Sociedades de Profissionais estão obrigadas a emitir no Padrão Nacional"],
    ["L66","A partir de 01/11/2025 todos os prestadores em Porto Alegre (RS) estão obrigados a emitir no Padrão Nacional"],
    ["L84","Para o regime especial de tributação configurado, emissão no Padrão Nacional é obrigatória em Belo Horizonte (MG)"],
    ["RNG6110","O campo Código Indicador de Operação deve ser preenchido"],
    ["00383","Lista de Serviço informada não possui desdobramento nacional"]
  ],
  abrasf: [
    ["E10","RPS já informado (número de RPS duplicado no lote)"],
    ["E17","Data de emissão do RPS não pode ser inferior à data de habilitação do prestador"],
    ["E29","O código de serviço prestado não permite retenção de ISS"],
    ["E30","Item da lista de serviço inexistente"],
    ["E36","O regime de tributação informado difere do registrado na Prefeitura"],
    ["E043","Inscrição Municipal do prestador não encontrada na base de dados do município"],
    ["E051","Inscrição Municipal do tomador do serviço incorreta"],
    ["E053","IM do tomador só deve ser preenchida para tomadores estabelecidos neste município"],
    ["E090","Número do RPS/DPS inválido"],
    ["E093","Série informada inválida"],
    ["E144","Natureza da operação inválida"],
    ["E165","Campo AliquotaServicos informado incorretamente"],
    ["E166","Regime especial de tributação incorreto"],
    ["E174","A natureza de operação selecionada exige a retenção de ISS"],
    ["E175","Contribuinte não está autorizado a emitir NFS-e com esta natureza de operação"],
    ["E179","Erro na autenticação do webservice"],
    ["E186","Campo valorIss informado incorretamente"],
    ["E328","Opção pelo Simples Nacional não consta do cadastro do contribuinte"],
    ["E329","Apenas serviços tributados podem sofrer retenção de ISSQN"],
    ["E337","A retenção informada no XML não é compatível com a regra do município"],
    ["E347","CNPJ/CPF do prestador não autorizado a emitir NFS-e"],
    ["E501","Valor do ISS informado incorretamente"],
    ["E505","Código de cancelamento não existe na tabela de erros e alertas"],
    ["E506","Código de cancelamento correto para uso em cancelamentos"],
    ["E507","O valor do ISS deve ser ZERO para a natureza escolhida"],
    ["E512","Valor da Base de Cálculo incorreto"],
    ["E513","Valor Líquido incorreto"],
    ["E522","Data de emissão do RPS não pode ser inferior à data de hoje menos o prazo limite"]
  ],
};

/* Sugestões de título amigável (3 por erro) para acelerar o preenchimento da Aba 2 */
const TITLE_SUGGESTIONS = {
  E0010:["Série da nota fora do permitido para o seu tipo de emissor","Número de série inválido para esta nota","A série utilizada não é válida para seu cadastro"],
  E0014:["Este número de nota já foi utilizado","Número de RPS/DPS duplicado","Já existe uma nota emitida com este número"],
  E0025:["Data da nota anterior à liberação do seu cadastro","Competência informada não é permitida ainda","A data desta nota é anterior à sua habilitação no sistema nacional"],
  E0032:["Dados cadastrais da empresa incompletos","Cadastro da empresa precisa ser corrigido","Informações da empresa estão incorretas no sistema nacional"],
  E0038:["Município ainda não está habilitado para emissão","Convênio do município não está ativo","Seu município não está liberado para emitir notas no momento"],
  E0060:["Nota tributada no município do prestador","ISS retido para o município onde você presta o serviço","Tributação definida para o prestador"],
  E0061:["Nota tributada no município do tomador","ISS retido para o município do seu cliente","Tributação definida para o tomador do serviço"],
  E0081:["Alíquota do Simples Nacional não configurada","Falta definir a alíquota do Simples para este mês","Sua alíquota do Simples Nacional não foi encontrada"],
  E0093:["Município ainda não aceita emissão pelo padrão nacional","Seu município não está configurado para o Emissor Nacional","Emissão pelo padrão nacional não disponível para este município"],
  E0116:["Inscrição Municipal não informada","Falta a Inscrição Municipal da sua empresa","É necessário informar a Inscrição Municipal para emitir"],
  E0120:["Inscrição Municipal não deveria ter sido informada","Remova a Inscrição Municipal deste cadastro","IM informada indevidamente para este município"],
  E0160:["Regime tributário diferente do cadastrado no Simples Nacional","Divergência entre o regime informado e o Simples Nacional","Seu regime de tributação não corresponde ao cadastro oficial"],
  E0240:["CEP do cliente não encontrado","Endereço do tomador não corresponde ao município informado","CEP informado é inválido para este município"],
  E0304:["Código complementar municipal não preenchido corretamente","Falta informar o código complementar exigido pelo município","Código complementar do município está incorreto"],
  E0310:["Código de serviço não encontrado na lista nacional","Código de tributação informado não existe","Serviço não corresponde a nenhum código nacional válido"],
  E0312:["Código de serviço não é aceito pelo seu município nesta data","Município não administra este código de tributação","Este código não está disponível para a competência informada"],
  E0370:["Faltam informações sobre a obra","Dados da construção/obra são obrigatórios para este serviço","Informe os dados de obra exigidos para este tipo de serviço"],
  E0713:["Informações do Simples Nacional não deveriam estar preenchidas","Campos do Simples Nacional inválidos para quem não é optante","Remova os dados do Simples Nacional deste cadastro"],
  E1010:["Sua empresa precisa emitir pelo Padrão Nacional","Emissão obrigatória no Padrão Nacional a partir de outubro/2025","Sociedades de Profissionais devem migrar para o Padrão Nacional"],
  E1011:["Empresas do Simples Nacional devem emitir pelo Padrão Nacional","Migração obrigatória para o Padrão Nacional a partir de novembro/2025","Seu regime exige emissão pelo Padrão Nacional"],
  GW3000:["Código de tributação inválido","O código informado não é reconhecido pelo sistema","Verifique o código de serviço utilizado nesta nota"],
  L64:["Sociedades de Profissionais devem emitir pelo Padrão Nacional","Migração obrigatória desde outubro/2023","Seu tipo de empresa exige emissão no Padrão Nacional"],
  L66:["Porto Alegre exige emissão pelo Padrão Nacional","Prestadores de Porto Alegre devem migrar a partir de nov/2025","Seu município tornou obrigatório o Padrão Nacional"],
  L84:["Belo Horizonte exige Padrão Nacional para seu regime especial","Seu regime especial só pode emitir pelo Padrão Nacional em BH","Migração obrigatória para o Padrão Nacional em Belo Horizonte"],
  RNG6110:["Falta informar o indicador de operação","Campo obrigatório não preenchido: indicador de operação","Indicador de operação ausente na nota"],
  "00383":["Este serviço não tem equivalente no padrão nacional","Código de serviço sem correspondência na lista nacional","Serviço incompatível com o desdobramento nacional"],
  E10:["Número de RPS já utilizado neste lote","RPS duplicado","Já existe um RPS com este número no lote enviado"],
  E17:["Data da nota anterior à sua habilitação","Esta data é anterior ao início da sua emissão","Data de emissão inválida para o seu cadastro"],
  E29:["Este serviço não permite retenção de ISS","Retenção de ISS não aplicável a este código de serviço","Serviço incompatível com retenção do imposto"],
  E30:["Item da lista de serviços não encontrado","Código de serviço inexistente","Este código de serviço não é válido no seu município"],
  E36:["Regime de tributação diferente do registrado na Prefeitura","Divergência entre seu cadastro e a Prefeitura","Atualize seu regime tributário junto à Prefeitura"],
  E043:["Inscrição Municipal não encontrada","Seu cadastro municipal não foi localizado","IM do prestador não consta na base da Prefeitura"],
  E051:["Inscrição Municipal do cliente está incorreta","IM do tomador inválida","Verifique a Inscrição Municipal informada para o cliente"],
  E053:["IM do cliente não deveria ser informada","Inscrição Municipal só é exigida para clientes do mesmo município","Remova a IM informada para este tomador"],
  E090:["Número do RPS/DPS inválido","Formato do RPS/DPS está incorreto","Número informado não é válido para esta nota"],
  E093:["Série informada é inválida","Esta série não está habilitada para sua empresa","Verifique a série utilizada na nota"],
  E144:["Natureza da operação inválida","Tipo de operação não reconhecido","Verifique a natureza da operação selecionada"],
  E165:["Alíquota de serviços informada incorretamente","Valor de alíquota inválido","Verifique a alíquota aplicada a este serviço"],
  E166:["Regime especial de tributação incorreto","Este regime especial não é válido para sua empresa","Verifique o regime especial selecionado"],
  E174:["Esta operação exige retenção de ISS","Retenção de ISS obrigatória para esta natureza","Falta reter o ISS para este tipo de operação"],
  E175:["Sua empresa não pode usar esta natureza de operação","Natureza de operação não autorizada para seu cadastro","Esta operação não é permitida para o seu perfil"],
  E179:["Falha de autenticação com a Prefeitura","Não foi possível autenticar no webservice municipal","Erro de comunicação com o sistema da Prefeitura"],
  E186:["Valor do ISS informado incorretamente","Verifique o valor do ISS calculado","Valor de ISS inconsistente com a nota"],
  E328:["Opção pelo Simples Nacional não encontrada","Seu cadastro não consta como optante do Simples","Simples Nacional não está registrado para sua empresa"],
  E329:["Apenas serviços tributados podem ter retenção de ISS","Este serviço não permite retenção","Retenção não aplicável a serviços não tributados"],
  E337:["Retenção informada não é compatível com a regra do município","Configuração de retenção divergente da Prefeitura","Ajuste a retenção conforme as regras municipais"],
  E347:["Seu CNPJ/CPF não está autorizado a emitir notas","Empresa não habilitada para emissão de NFS-e","Cadastro não autorizado pela Prefeitura"],
  E501:["Valor do ISS está incorreto","Verifique o cálculo do imposto ISS","Valor informado para o ISS não é válido"],
  E505:["Código de cancelamento não encontrado","Motivo de cancelamento inválido","Use um código de cancelamento válido"],
  E506:["Use o código de cancelamento adequado","Código de cancelamento precisa ser ajustado","Selecione o motivo de cancelamento correto"],
  E507:["O valor do ISS deve ser zero para esta natureza","Esta operação não pode ter valor de ISS","Remova o valor de ISS desta nota"],
  E512:["Valor da Base de Cálculo está incorreto","Verifique o valor base usado no cálculo do imposto","Base de cálculo inconsistente com a nota"],
  E513:["Valor líquido da nota está incorreto","Verifique o valor líquido informado","Valor líquido não corresponde ao esperado"],
  E522:["Data de emissão fora do prazo permitido","Esta nota não pode ser emitida com data tão antiga","Prazo para emissão retroativa expirado"],
  SOAP_EXCEPTION:["Erro técnico ao comunicar com o sistema da Prefeitura","Falha inesperada no envio da nota","Não foi possível processar sua solicitação no momento"],
  ABRASF_VERSION:["Versão do layout ABRASF não é mais aceita","Seu município mudou a versão exigida do ABRASF","Atualização de versão necessária para emissão"],
  AUTH_ERROR:["Falha na autenticação com a Prefeitura","Credenciais ou certificado não reconhecidos","Não foi possível validar seu acesso ao sistema municipal"],
  TIMEOUT:["Tempo de conexão com a Prefeitura esgotado","O sistema municipal não respondeu a tempo","Falha de conexão ao transmitir a nota"]
};

function buildSeed(){
  const errors = [];
  for(const group of Object.keys(SEED_RAW)){
    for(const [code, msg] of SEED_RAW[group]){
      errors.push({
        code, group, original_message: msg,
        match_patterns: [code], requires_prefecture: false, status: "nao_mapeado",
        client_facing: { title:"", title_suggestions: TITLE_SUGGESTIONS[code] || [], description:"", steps:[], extra_tip:"" },
        agent_flow: { flow_steps:[], start_step_id:null, post_fix_followup:{ enabled:false, message:"" }, escalation:{ after_attempts:3, message:"", zendesk_url:"" }, system_prompt_preview:"" }
      });
    }
  }
  return { version:"1.0", exported_at:new Date().toISOString(), errors };
}

const GROUP_LABELS = { portal_nacional:"Portal Nacional", abrasf:"ABRASF", sefaz_nfe55:"SEFAZ NF-e 55" };
const STATUS_LABELS = { nao_mapeado:"Não mapeado", em_revisao:"Em revisão", pronto:"Pronto" };

/* ================= ESTADO ================= */
let state = null;
let selectedCode = null;
let saveTimer = null;
let lastSavedAt = null;
let isSaving = false;
let statusFilter = new Set();

function setSyncStatus(kind, text){
  const dot = document.getElementById("syncDot");
  const label = document.getElementById("syncText");
  dot.className = "sync-dot " + kind;
  label.textContent = text;
}

/* ================= GIST: LOAD / SAVE ================= */
async function loadFromGist(){
  setSyncStatus("loading","Carregando...");
  try{
    const res = await fetch(GIST_API, { headers: { Authorization: "token " + getToken() } });
    if(!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();
    const file = data.files && data.files[GIST_FILE];
    if(file && file.content){
      state = JSON.parse(file.content);
      const before = state.errors.length;
      state.errors = state.errors.filter(e => e.group !== "xml_soap");
      if(state.errors.length !== before) await saveToGist(true);
      setSyncStatus("ok","Sincronizado");
    } else {
      state = buildSeed();
      await saveToGist(true);
    }
  } catch(err){
    console.error("Erro ao carregar Gist:", err);
    const cached = localStorage.getItem("nfse-errors-cache");
    if(cached){
      state = JSON.parse(cached);
      setSyncStatus("err","Erro ao sincronizar (usando cache local)");
    } else {
      state = buildSeed();
      setSyncStatus("err","Erro ao sincronizar (dados de seed locais)");
    }
  }
  localStorage.setItem("nfse-errors-cache", JSON.stringify(state));
  render();
}

async function saveToGist(silent){
  if(isSaving){ scheduleSave(); return; }
  isSaving = true;
  if(!silent) setSyncStatus("loading","Salvando...");
  try{
    const res = await fetch(GIST_API, {
      method:"PATCH",
      headers:{ Authorization:"token " + getToken(), "Content-Type":"application/json" },
      body: JSON.stringify({ files: { [GIST_FILE]: { content: JSON.stringify(state, null, 2) } } })
    });
    if(!res.ok) throw new Error("HTTP " + res.status);
    lastSavedAt = new Date();
    localStorage.setItem("nfse-errors-cache", JSON.stringify(state));
    setSyncStatus("ok","Sincronizado às " + lastSavedAt.toLocaleTimeString());
  } catch(err){
    console.error("Erro ao salvar Gist:", err);
    localStorage.setItem("nfse-errors-cache", JSON.stringify(state));
    setSyncStatus("err","Erro ao sincronizar (alterações salvas só localmente)");
  } finally {
    isSaving = false;
  }
}

function scheduleSave(){
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => saveToGist(false), 2000);
}

/* ================= RENDER SIDEBAR ================= */
function render(){
  renderProgress();
  renderSidebar();
  renderMain();
}

function renderProgress(){
  const total = state.errors.length;
  const done = state.errors.filter(e => e.status === "pronto").length;
  const pct = total ? Math.round(done/total*100) : 0;
  document.getElementById("progressLabel").textContent = `${done} / ${total} erros mapeados (${pct}%)`;
  document.getElementById("progressFill").style.width = pct + "%";
}

function renderFilters(){
  const statusBox = document.getElementById("statusFilters");
  statusBox.innerHTML = Object.entries(STATUS_LABELS).map(([k,v]) =>
    `<span class="chip ${statusFilter.has(k)?'active':''}" data-status="${k}">${v}</span>`
  ).join('');
  statusBox.querySelectorAll(".chip").forEach(chip => chip.onclick = () => {
    const k = chip.dataset.status;
    statusFilter.has(k) ? statusFilter.delete(k) : statusFilter.add(k);
    renderSidebar();
  });
}

let activeGroup = Object.keys(GROUP_LABELS)[0];
let activeAgent = "";  // "" = todos, "calais" = primeiros 13 portal_nacional, "rafa" = últimos 13

function getAgentCodes(){
  const portalErrors = state.errors
    .filter(e => e.group === "portal_nacional")
    .sort((a,b) => a.code.localeCompare(b.code));
  const half = Math.ceil(portalErrors.length / 2);
  return {
    calais: new Set(portalErrors.slice(0, half).map(e => e.code)),
    rafa:   new Set(portalErrors.slice(half).map(e => e.code))
  };
}

document.querySelectorAll(".agents-dropdown-item").forEach(item => {
  item.onclick = () => {
    activeAgent = item.dataset.agent;
    // Se selecionou agente, força aba portal_nacional
    if(activeAgent) activeGroup = "portal_nacional";
    updateAgentsBtn();
    renderSidebar();
  };
});

function updateAgentsBtn(){
  const btn = document.getElementById("agentsBtn");
  const labels = { calais:"Calais", rafa:"Rafa", "":"Agentes" };
  const label = labels[activeAgent] ?? "Agentes";
  btn.innerHTML = `${label}${activeAgent ? `<span class="agent-badge">${activeAgent==="calais"?"13":"13"}</span>` : ""}<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>`;
  btn.classList.toggle("active-agent", !!activeAgent);
  document.querySelectorAll(".agents-dropdown-item").forEach(el => {
    el.classList.toggle("active", el.dataset.agent === activeAgent);
  });
}

function renderGroupTabs(){
  const term = (document.getElementById("searchInput").value || "").toLowerCase();
  const agentCodes = activeAgent ? getAgentCodes()[activeAgent] : null;
  // Se agente ativo, só mostra aba portal_nacional (único grupo dos agentes)
  const visibleGroups = activeAgent ? ["portal_nacional"] : Object.keys(GROUP_LABELS);
  const tabsEl = document.getElementById("groupTabs");
  tabsEl.innerHTML = "";
  for(const key of visibleGroups){
    const label = GROUP_LABELS[key];
    const count = state.errors.filter(e => e.group === key &&
      (e.code.toLowerCase().includes(term) || (e.client_facing.title||"").toLowerCase().includes(term)) &&
      (statusFilter.size === 0 || statusFilter.has(e.status)) &&
      (!agentCodes || agentCodes.has(e.code))
    ).length;
    if(count === 0) continue;
    const tab = document.createElement("span");
    tab.className = "group-tab" + (activeGroup === key ? " active" : "");
    tab.textContent = label + " (" + count + ")";
    tab.onclick = () => { activeGroup = key; renderSidebar(); };
    tabsEl.appendChild(tab);
  }
  const available = visibleGroups.filter(k =>
    state.errors.some(e => e.group === k &&
      (e.code.toLowerCase().includes(term) || (e.client_facing.title||"").toLowerCase().includes(term)) &&
      (statusFilter.size === 0 || statusFilter.has(e.status)) &&
      (!agentCodes || agentCodes.has(e.code))
    )
  );
  if(available.length && !available.includes(activeGroup)) activeGroup = available[0];
}

function renderSidebar(){
  renderFilters();
  renderGroupTabs();
  const container = document.getElementById("groupsContainer");
  container.innerHTML = "";
  const term = (document.getElementById("searchInput").value || "").toLowerCase();
  const agentCodes = activeAgent ? getAgentCodes()[activeAgent] : null;
  const items = state.errors.filter(e => e.group === activeGroup &&
    (e.code.toLowerCase().includes(term) || (e.client_facing.title||"").toLowerCase().includes(term)) &&
    (statusFilter.size === 0 || statusFilter.has(e.status)) &&
    (!agentCodes || agentCodes.has(e.code))
  );
  for(const e of items){
    const row = document.createElement("div");
    row.className = "error-item" + (e.code === selectedCode ? " active" : "");
    row.innerHTML = `<span class="badge ${e.status}"></span><span class="code">${escapeHtml(e.code)}</span><span class="title">${escapeHtml(e.client_facing.title || e.original_message)}</span>`;
    row.onclick = () => { selectedCode = e.code; viewMode = "errors"; setHash(activeTab); render(); };
    container.appendChild(row);
  }
}

document.getElementById("searchInput").addEventListener("input", renderSidebar);

/* ================= MAIN FORM ================= */
let activeTab = "identificacao";
let viewMode = "errors";
const VALID_TABS = ["identificacao","cliente","agente","diagrama","status"];

function getSelected(){ return state.errors.find(e => e.code === selectedCode); }

function setHash(h){
  if(location.hash !== "#" + h) location.hash = h;
}

function applyHash(){
  const h = location.hash.replace(/^#/, "");
  if(h === "ajuda"){
    viewMode = "ajuda";
  } else if(VALID_TABS.includes(h)){
    viewMode = "errors";
    activeTab = h;
  }
}

window.addEventListener("hashchange", () => { applyHash(); render(); });

function renderMain(){
  const main = document.getElementById("mainArea");
  if(viewMode === "ajuda"){
    renderHelp(main);
    return;
  }
  const err = getSelected();
  if(!err){
    main.innerHTML = '<div class="empty-state">Selecione um erro na lista à esquerda, ou crie um novo.</div>';
    return;
  }
  main.innerHTML = `
    <div class="tabs">
      <div class="tab ${activeTab==='identificacao'?'active':''}" data-tab="identificacao">1. Identificação do Erro</div>
      <div class="tab ${activeTab==='cliente'?'active':''}" data-tab="cliente">2. Apresentação ao Cliente</div>
      <div class="tab ${activeTab==='agente'?'active':''}" data-tab="agente">3. Fluxo do Agente</div>
      <div class="tab ${activeTab==='diagrama'?'active':''}" data-tab="diagrama">4. Diagrama</div>
      <div class="tab ${activeTab==='status'?'active':''}" data-tab="status">5. Status de Mapeamento</div>
    </div>
    <div id="panelIdentificacao" class="panel ${activeTab==='identificacao'?'active':''}"></div>
    <div id="panelCliente" class="panel ${activeTab==='cliente'?'active':''}"></div>
    <div id="panelAgente" class="panel ${activeTab==='agente'?'active':''}"></div>
    <div id="panelDiagrama" class="panel ${activeTab==='diagrama'?'active':''}"></div>
    <div id="panelStatus" class="panel ${activeTab==='status'?'active':''}"></div>
  `;
  main.querySelectorAll(".tab").forEach(t => t.onclick = () => { activeTab = t.dataset.tab; viewMode = "errors"; setHash(activeTab); renderMain(); });
  renderTabIdentificacao(err);
  renderTabCliente(err);
  renderTabAgente(err);
  renderTabDiagrama(err);
  renderTabStatus(err);
}

function fieldChanged(){ scheduleSave(); renderSidebar(); renderProgress(); }

/* ----- ABA 1 ----- */
function renderTabIdentificacao(err){
  const p = document.getElementById("panelIdentificacao");
  p.innerHTML = `
    <div class="row">
      <div class="field">
        <label>Código do erro *</label>
        <input type="text" id="f_code" value="${escapeAttr(err.code)}">
      </div>
      <div class="field" style="flex:none;align-self:flex-end;margin-bottom:16px;">
        <button class="btn-ghost btn-sm" id="btnDuplicate" type="button">Duplicar erro</button>
      </div>
      <div class="field">
        <label>Grupo</label>
        <select id="f_group">
          ${Object.entries(GROUP_LABELS).map(([k,v]) => `<option value="${k}" ${err.group===k?'selected':''}>${v}</option>`).join('')}
        </select>
      </div>
    </div>
    <div class="field">
      <label>Mensagem original do sistema (referência)</label>
      <textarea readonly>${escapeHtml(err.original_message)}</textarea>
    </div>
    <div class="field">
      <label>Padrões de identificação</label>
      <div class="tags-input" id="f_patterns_wrap">
        ${err.match_patterns.map((t,i) => `<span class="tag">${escapeHtml(t)}<button data-i="${i}" class="rm-pattern">×</button></span>`).join('')}
        <input type="text" id="f_pattern_new" placeholder="Digite e pressione Enter">
      </div>
      <div class="hint">Termos que identificam esse erro no texto livre retornado pela API.</div>
    </div>
    <div class="row">
      <div class="field">
        <label class="toggle"><input type="checkbox" id="f_requires_prefecture" ${err.requires_prefecture?'checked':''}> Requer ação na Prefeitura/Portal Nacional?</label>
      </div>
    </div>
  `;
  document.getElementById("f_code").onchange = e => { err.code = e.target.value; selectedCode = err.code; fieldChanged(); };
  document.getElementById("f_group").onchange = e => { err.group = e.target.value; fieldChanged(); };
  document.getElementById("f_requires_prefecture").onchange = e => { err.requires_prefecture = e.target.checked; fieldChanged(); };
  const patInput = document.getElementById("f_pattern_new");
  patInput.onkeydown = e => {
    if(e.key === "Enter" && patInput.value.trim()){
      err.match_patterns.push(patInput.value.trim());
      patInput.value = "";
      fieldChanged(); renderTabIdentificacao(err);
    }
  };
  p.querySelectorAll(".rm-pattern").forEach(btn => btn.onclick = () => {
    err.match_patterns.splice(+btn.dataset.i, 1);
    fieldChanged(); renderTabIdentificacao(err);
  });
  document.getElementById("btnDuplicate").onclick = () => {
    const newCode = prompt("Código do erro duplicado:", err.code + "_COPIA");
    if(!newCode) return;
    if(state.errors.some(e => e.code === newCode)){ alert("Já existe um erro com esse código."); return; }
    const copy = JSON.parse(JSON.stringify(err));
    copy.code = newCode;
    copy.status = "em_revisao";
    state.errors.push(copy);
    selectedCode = newCode;
    fieldChanged();
    render();
  };
}

// Erro é considerado "pronto" quando a apresentação ao cliente (Aba 2) está completa;
// o fluxo do agente (Aba 3) é opcional e não bloqueia o status.
function validateReadyToShip(err){
  return !!(err.client_facing.title && htmlToText(err.client_facing.description) && err.client_facing.steps.some(s => htmlToText(s)));
}

/* ----- ABA 5 ----- */
function renderTabStatus(err){
  const p = document.getElementById("panelStatus");
  const checklist = [
    { label: "Identificação do erro preenchida (Aba 1)", done: !!(err.code && err.group) },
    { label: "Título e descrição para o cliente preenchidos (Aba 2)", done: !!(err.client_facing.title && htmlToText(err.client_facing.description)) },
    { label: "Pelo menos um passo de orientação ao cliente (Aba 2)", done: err.client_facing.steps.some(s => htmlToText(s)) },
    { label: "Fluxo do agente possui ao menos uma etapa (Aba 3)", done: err.agent_flow.flow_steps.length > 0 },
    { label: "Etapa inicial do fluxo definida (Aba 3)", done: !!err.agent_flow.start_step_id },
  ];
  const pending = checklist.filter(c => !c.done).length;
  p.innerHTML = `
    <div class="field">
      <label>Status de mapeamento</label>
      <select id="f_status">
        ${Object.entries(STATUS_LABELS).map(([k,v]) => `<option value="${k}" ${err.status===k?'selected':''}>${v}</option>`).join('')}
      </select>
      <div class="hint">Use esta etapa para concluir se o mapeamento deste erro está finalizado ou ainda em andamento.</div>
    </div>
    <div class="field">
      <label>Checklist de finalização</label>
      <ul class="status-checklist">
        ${checklist.map(c => `<li class="${c.done?'done':'pending'}">${c.done?'✓':'○'} ${escapeHtml(c.label)}</li>`).join('')}
      </ul>
      <div class="hint">${pending===0 ? 'Todos os itens essenciais estão preenchidos.' : `${pending} item(ns) pendente(s) antes de marcar como "Pronto".`}</div>
    </div>
  `;
  document.getElementById("f_status").onchange = e => {
    if(e.target.value === "pronto" && !validateReadyToShip(err)){
      alert("Preencha os campos obrigatórios das Abas 1 e 2 antes de marcar como Pronto.");
      e.target.value = err.status;
      return;
    }
    err.status = e.target.value; fieldChanged();
  };
}

/* ----- AJUDA ----- */
function renderHelp(main){
  // legacy no-op — help is now a modal (setupHelpModal)
}

/* ---- HELP MODAL ---- */
const HELP_PAGES = [
  {
    title: "O que é esta ferramenta",
    content: `
      <div class="help-step-label">PASSO 1 DE 7</div>
      <h3>O que é esta ferramenta?</h3>
      <p class="help-lead">Uma plataforma para mapear os erros de emissão de NFS-e — traduzindo mensagens técnicas em orientações claras para o cliente e roteiros de atendimento para o agente de suporte.</p>
      <ul>
        <li><b>Centraliza o conhecimento:</b> cada erro tem um espaço dedicado com título amigável, descrição, passo a passo e fluxo de atendimento.</li>
        <li><b>Salva automaticamente:</b> todas as alterações ficam armazenadas de forma compartilhada. Qualquer pessoa que abrir a ferramenta verá exatamente os mesmos dados.</li>
        <li><b>Sem instalação:</b> funciona direto no navegador — basta acessar o link.</li>
      </ul>
      <div class="help-section">ORGANIZAÇÃO</div>
      <ul>
        <li>Os erros são agrupados por categoria: <b>Portal Nacional</b>, <b>ABRASF</b> e <b>SEFAZ NF-e 55</b>.</li>
        <li>Cada erro passa por etapas de preenchimento até ser marcado como <span class="help-badge help-badge-green">Pronto</span>.</li>
      </ul>
      <div class="help-tip"><b>Dica:</b> use o indicador de sincronização no topo da tela para saber se as alterações já foram salvas. O ícone de disquete força o salvamento imediato.</div>
    `
  },
  {
    title: "Encontrando um erro",
    content: `
      <div class="help-step-label">PASSO 2 DE 7</div>
      <h3>Encontrando um erro</h3>
      <p class="help-lead">Use a barra lateral esquerda para navegar pelos erros já cadastrados ou para criar um novo.</p>
      <div class="help-section">BUSCA</div>
      <ul>
        <li>Digite o <b>código do erro</b> (ex: E0032) ou parte do <b>título</b> no campo de busca no topo da lista.</li>
        <li>A lista filtra em tempo real enquanto você digita.</li>
      </ul>
      <div class="help-section">FILTROS</div>
      <ul>
        <li>Clique nas abas de grupo (<b>Portal Nacional</b>, <b>ABRASF</b>, <b>SEFAZ NF-e 55</b>) para ver só os erros daquela categoria.</li>
        <li>Use os filtros de status para mostrar apenas erros <span class="help-badge help-badge-gray">Não mapeado</span>, <span class="help-badge help-badge-yellow">Em revisão</span> ou <span class="help-badge help-badge-green">Pronto</span>.</li>
      </ul>
      <div class="help-section">CRIANDO UM NOVO ERRO</div>
      <ul>
        <li>Clique em <b>+ Novo Erro</b> no canto superior direito para criar um registro em branco.</li>
        <li>Se um novo erro for parecido com um já existente, use o botão <b>Duplicar</b> na Aba 1 para copiar o conteúdo e ajustar só o que for diferente.</li>
      </ul>
      <div class="help-tip"><b>Dica:</b> a barra de progresso no topo da lista mostra o percentual de erros já marcados como "Pronto".</div>
    `
  },
  {
    title: "Aba 1 — Identificação",
    content: `
      <div class="help-step-label">PASSO 3 DE 7</div>
      <h3>Aba 1 — Identificação do Erro</h3>
      <p class="help-lead">Aqui ficam os dados básicos que identificam e categorizam o erro dentro da ferramenta.</p>
      <ul>
        <li><b>Código do erro:</b> identificador único (ex: E0032). Usado como referência em toda a ferramenta.</li>
        <li><b>Grupo:</b> categoria do erro — Portal Nacional, ABRASF ou SEFAZ NF-e 55. Define em qual aba da lista lateral o erro aparece.</li>
        <li><b>Mensagem original do sistema:</b> o texto técnico exato que a API retorna. Serve de referência — não é exibido ao cliente.</li>
        <li><b>Requer ação na Prefeitura / Portal Nacional?</b> Marque quando a resolução depende de algo fora do sistema da empresa (ex: cadastro no portal municipal).</li>
      </ul>
      <div class="help-section">AÇÕES DISPONÍVEIS</div>
      <ul>
        <li><b>Duplicar erro:</b> cria uma cópia deste erro com um novo código — útil para erros muito parecidos.</li>
        <li><b>Excluir erro:</b> remove o erro permanentemente (com confirmação).</li>
      </ul>
      <div class="help-tip"><b>Dica:</b> preencher o código e o grupo é obrigatório para que o erro apareça corretamente na lista lateral.</div>
    `
  },
  {
    title: "Aba 2 — Apresentação ao Cliente",
    content: `
      <div class="help-step-label">PASSO 4 DE 7</div>
      <h3>Aba 2 — Apresentação ao Cliente</h3>
      <p class="help-lead">É aqui que você define o que o cliente vai ler quando esse erro acontecer — em linguagem simples e acessível, sem termos técnicos.</p>
      <ul>
        <li><b>Título amigável:</b> frase curta que resume o problema para o cliente. Há sugestões prontas — clique em uma para usá-la como ponto de partida.</li>
        <li><b>Descrição amigável:</b> explica o que aconteceu e por que, de forma clara e empática.</li>
      </ul>
      <div class="help-section">PASSOS DE ORIENTAÇÃO</div>
      <ul>
        <li>Lista ordenada do que o cliente (ou o agente, em nome dele) deve fazer para resolver o erro.</li>
        <li>Clique em <b>+ Adicionar passo</b> para incluir mais itens.</li>
        <li>Arraste os itens para reordenar — o cliente vai ler na ordem em que aparecem.</li>
      </ul>
      <div class="help-tip"><b>Dica:</b> título, descrição e pelo menos um passo são obrigatórios para marcar o erro como "Pronto" na Aba 5.</div>
    `
  },
  {
    title: "Aba 3 — Fluxo do Agente",
    content: `
      <div class="help-step-label">PASSO 5 DE 7</div>
      <h3>Aba 3 — Fluxo do Agente</h3>
      <p class="help-lead">Aqui você monta o roteiro de conversa que o agente de suporte deve seguir ao atender um cliente com esse erro.</p>
      <div class="help-section">TIPOS DE ETAPA</div>
      <ul>
        <li><b>Pergunta:</b> o agente faz uma pergunta ao cliente. As respostas possíveis podem ser Sim/Não, múltipla escolha ou texto livre — escolha conforme o que for mais adequado.</li>
        <li><b>Período (calendário):</b> solicita ao cliente que informe uma data ou um intervalo de datas — útil para corrigir períodos de vendas.</li>
      </ul>
      <div class="help-section">DESTINOS DE CADA RESPOSTA</div>
      <ul>
        <li><b>Ir para outra etapa:</b> a conversa continua em outra pergunta do fluxo.</li>
        <li><b>Mensagem final:</b> exibe uma mensagem de conclusão ao cliente e encerra o atendimento desse erro.</li>
        <li><b>Aplicar correção:</b> indica que o agente deve executar uma ação corretiva no sistema e exibir a confirmação ao cliente.</li>
      </ul>
      <div class="help-section">ETAPA INICIAL</div>
      <ul>
        <li>Defina qual etapa é a <b>primeira</b> da conversa — por onde o atendimento começa.</li>
        <li>O <b>Prompt do Sistema</b> (gerado automaticamente no painel ao lado) reflete o fluxo montado aqui e pode ser copiado para usar diretamente no agente.</li>
      </ul>
      <div class="help-tip"><b>Dica:</b> ter pelo menos uma etapa criada e a etapa inicial definida é obrigatório para marcar o erro como "Pronto".</div>
    `
  },
  {
    title: "Aba 4 — Diagrama",
    content: `
      <div class="help-step-label">PASSO 6 DE 7</div>
      <h3>Aba 4 — Diagrama</h3>
      <p class="help-lead">Visualização gráfica do fluxo montado na Aba 3 — útil para revisar a lógica do atendimento de forma visual.</p>
      <ul>
        <li>Cada <b>caixa colorida</b> representa uma etapa. As <b>setas</b> mostram para onde cada resposta leva.</li>
        <li>A <b>legenda de cores</b> indica o tipo de destino: roxo = próxima etapa, dourado = mensagem final, verde = aplicar correção.</li>
      </ul>
      <div class="help-section">INTERAÇÕES NO DIAGRAMA</div>
      <ul>
        <li><b>Arrastar caixas:</b> reorganize livremente clicando e arrastando qualquer caixa.</li>
        <li><b>Ligar etapas:</b> arraste a bolinha de saída de uma etapa até outra caixa para criar ou alterar a conexão.</li>
        <li><b>Editar etapa:</b> clique no ícone ✎ para abrir a etapa na Aba 3 e editar o conteúdo.</li>
        <li><b>Excluir etapa:</b> clique em × na caixa (com confirmação).</li>
      </ul>
      <div class="help-section">VISÃO DE CAMINHOS</div>
      <ul>
        <li>Clique em <b>⟳ Reorganizar layout</b> para ver cada caminho possível do fluxo como uma coluna independente — sem linhas cruzadas, facilitando a leitura.</li>
        <li>Use <b>← Voltar ao editor</b> para retornar ao canvas interativo.</li>
      </ul>
      <div class="help-tip"><b>Dica:</b> alterações de conexão feitas no diagrama também atualizam o fluxo da Aba 3 automaticamente.</div>
    `
  },
  {
    title: "Aba 5 — Finalizando",
    content: `
      <div class="help-step-label">PASSO 7 DE 7</div>
      <h3>Aba 5 — Status de Mapeamento</h3>
      <p class="help-lead">Aqui você acompanha e define o status de conclusão do mapeamento deste erro.</p>
      <div class="help-section">STATUS DISPONÍVEIS</div>
      <ul>
        <li><span class="help-badge help-badge-gray">Não mapeado</span> — ainda não foi iniciado ou está em etapas iniciais.</li>
        <li><span class="help-badge help-badge-yellow">Em revisão</span> — o conteúdo existe mas ainda precisa de ajustes ou validação.</li>
        <li><span class="help-badge help-badge-green">Pronto</span> — mapeamento completo, pronto para uso pelo agente de suporte.</li>
      </ul>
      <div class="help-section">CHECKLIST DE FINALIZAÇÃO</div>
      <ul>
        <li>A ferramenta exibe um checklist indicando o que ainda precisa ser preenchido antes de marcar como "Pronto".</li>
        <li>Os itens obrigatórios são: identificação do erro (Aba 1), título e descrição amigável (Aba 2), pelo menos um passo de orientação (Aba 2), pelo menos uma etapa no fluxo do agente (Aba 3) e a etapa inicial definida (Aba 3).</li>
      </ul>
      <div class="help-section">EXPORTAR</div>
      <ul>
        <li>Clique em <b>Exportar JSON</b> no topo da tela para baixar um arquivo com todos os erros mapeados — útil para backup ou integração com outras ferramentas.</li>
      </ul>
      <div class="help-tip"><b>Dica:</b> você pode voltar a esta ajuda a qualquer momento clicando no ícone <b>?</b> no topo da tela.</div>
    `
  }
];

function setupHelpModal(){
  const overlay = document.getElementById("helpOverlay");
  const closeBtn = document.getElementById("helpClose");
  const prevBtn  = document.getElementById("helpPrev");
  const nextBtn  = document.getElementById("helpNext");
  const counter  = document.getElementById("helpCounter");
  const stepper  = document.getElementById("helpStepper");
  const topicsList = document.getElementById("helpTopicsList");
  const contentArea = document.getElementById("helpContentArea");
  let currentPage = 0;
  const total = HELP_PAGES.length;

  function renderStepper(){
    stepper.innerHTML = "";
    HELP_PAGES.forEach((_, i) => {
      if(i > 0){
        const line = document.createElement("div");
        line.className = "help-step-line" + (i <= currentPage ? " done" : "");
        stepper.appendChild(line);
      }
      const circle = document.createElement("div");
      if(i < currentPage) circle.className = "help-step-circle done";
      else if(i === currentPage) circle.className = "help-step-circle active";
      else circle.className = "help-step-circle";
      circle.innerHTML = i < currentPage
        ? `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`
        : String(i + 1);
      circle.style.cursor = "pointer";
      circle.addEventListener("click", () => goTo(i));
      stepper.appendChild(circle);
    });
  }

  function renderTopics(){
    topicsList.innerHTML = "";
    HELP_PAGES.forEach((page, i) => {
      const item = document.createElement("div");
      item.className = "help-topic" + (i === currentPage ? " active" : "") + (i < currentPage ? " done-topic" : "");
      const icon = document.createElement("div");
      icon.className = "ht-icon";
      if(i < currentPage) icon.innerHTML = `<svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
      else if(i === currentPage) icon.style.background = "var(--primary)";
      item.appendChild(icon);
      const label = document.createElement("span");
      label.textContent = page.title;
      item.appendChild(label);
      item.addEventListener("click", () => goTo(i));
      topicsList.appendChild(item);
    });
  }

  function renderContent(){
    contentArea.innerHTML = HELP_PAGES[currentPage].content;
    contentArea.scrollTop = 0;
    counter.textContent = (currentPage + 1) + " / " + total;
    prevBtn.disabled = currentPage === 0;
    prevBtn.style.opacity = currentPage === 0 ? "0.4" : "1";
    nextBtn.textContent = currentPage === total - 1 ? "Fechar" : "Próximo ›";
  }

  function goTo(i){
    currentPage = Math.max(0, Math.min(total - 1, i));
    renderStepper();
    renderTopics();
    renderContent();
  }

  function open(){
    currentPage = 0;
    overlay.style.display = "flex";
    goTo(0);
  }
  function close(){
    overlay.style.display = "none";
  }

  closeBtn.addEventListener("click", close);
  overlay.addEventListener("click", e => { if(e.target === overlay) close(); });
  prevBtn.addEventListener("click", () => goTo(currentPage - 1));
  nextBtn.addEventListener("click", () => {
    if(currentPage === total - 1) close();
    else goTo(currentPage + 1);
  });

  document.getElementById("btnHelp").onclick = open;
}

/* ----- ABA 2 ----- */
function renderTabCliente(err){
  const p = document.getElementById("panelCliente");
  const missingTitle = !err.client_facing.title;
  const missingDesc = !htmlToText(err.client_facing.description);
  const suggestions = (err.client_facing.title_suggestions && err.client_facing.title_suggestions.length)
    ? err.client_facing.title_suggestions
    : (TITLE_SUGGESTIONS[err.code] || []);
  p.innerHTML = `
    <div class="two-col">
      <div>
        <div class="field ${missingTitle?'invalid':''}">
          <label>Título amigável *</label>
          ${suggestions.length ? `<div class="title-suggestions" id="titleSuggestions">
            ${suggestions.map((s,i) => `<button type="button" class="title-suggestion" data-i="${i}">${escapeHtml(s)}</button>`).join('')}
          </div>` : ''}
          <input type="text" id="c_title" placeholder="Selecione uma sugestão acima ou escreva livremente" value="${escapeAttr(err.client_facing.title)}">
          ${missingTitle?'<div class="invalid-msg">Campo obrigatório para status Pronto</div>':''}
        </div>
        <div class="field ${missingDesc?'invalid':''}">
          <label>Descrição amigável *</label>
          <div class="rich-editor" id="c_description"></div>
        </div>
        <div class="field">
          <label>Passo a passo de solução</label>
          <div id="stepsList"></div>
          <button class="btn-ghost btn-sm" id="btnAddStep">+ Adicionar passo</button>
        </div>
        <div class="field">
          <label>Tip extra / aviso adicional</label>
          <div class="rich-editor" id="c_tip"></div>
        </div>
      </div>
      <div>
        <div class="preview-card">
          <h3 id="prevTitle">${escapeHtml(err.client_facing.title) || "Título do erro"}</h3>
          <div id="prevDesc">${err.client_facing.description || "<p>Descrição amigável aparecerá aqui.</p>"}</div>
          <ol id="prevSteps"></ol>
          <div class="tip" id="prevTip" style="${htmlToText(err.client_facing.extra_tip)?'':'display:none'}">${err.client_facing.extra_tip || ""}</div>
        </div>
      </div>
    </div>
  `;
  document.getElementById("c_title").oninput = e => { err.client_facing.title = e.target.value; document.getElementById("prevTitle").textContent = e.target.value || "Título do erro"; fieldChanged(); };
  const suggestionsBox = document.getElementById("titleSuggestions");
  if(suggestionsBox){
    suggestionsBox.querySelectorAll(".title-suggestion").forEach(btn => btn.onclick = () => {
      const value = suggestions[+btn.dataset.i];
      err.client_facing.title = value;
      document.getElementById("c_title").value = value;
      document.getElementById("prevTitle").textContent = value;
      fieldChanged();
      renderTabCliente(err);
    });
  }
  mountRichEditor(document.getElementById("c_description"), err.client_facing.description, "Descreva o passo a passo para solução...", html => {
    err.client_facing.description = html;
    document.getElementById("prevDesc").innerHTML = html || "<p>Descrição amigável aparecerá aqui.</p>";
    fieldChanged();
  });
  mountRichEditor(document.getElementById("c_tip"), err.client_facing.extra_tip, "Aviso ou dica extra (opcional)...", html => {
    err.client_facing.extra_tip = html;
    const tipEl = document.getElementById("prevTip");
    tipEl.innerHTML = html || "";
    tipEl.style.display = htmlToText(html) ? "" : "none";
    fieldChanged();
  });
  document.getElementById("btnAddStep").onclick = () => { err.client_facing.steps.push(""); fieldChanged(); renderTabCliente(err); };
  renderSteps(err);
}

function renderSteps(err){
  const list = document.getElementById("stepsList");
  list.innerHTML = "";
  err.client_facing.steps.forEach((step, i) => {
    const row = document.createElement("div");
    row.className = "step-item";
    row.draggable = true;
    row.dataset.i = i;
    row.innerHTML = `<div class="num">${i+1}</div><div class="rich-editor" style="flex:1;"></div><button class="rm">×</button>`;
    mountRichEditor(row.querySelector(".rich-editor"), step, "Descreva este passo...", html => {
      err.client_facing.steps[i] = html;
      updatePreviewSteps(err);
      fieldChanged();
    });
    row.querySelector(".rm").onclick = () => { err.client_facing.steps.splice(i,1); fieldChanged(); renderTabCliente(err); };
    row.ondragstart = e => e.dataTransfer.setData("text/plain", i);
    row.ondragover = e => e.preventDefault();
    row.ondrop = e => {
      e.preventDefault();
      const from = +e.dataTransfer.getData("text/plain");
      const to = i;
      const [moved] = err.client_facing.steps.splice(from,1);
      err.client_facing.steps.splice(to,0,moved);
      fieldChanged(); renderTabCliente(err);
    };
    list.appendChild(row);
  });
  updatePreviewSteps(err);
}

function updatePreviewSteps(err){
  const ol = document.getElementById("prevSteps");
  if(!ol) return;
  ol.innerHTML = err.client_facing.steps.map(s => `<li>${s}</li>`).join('');
}

/* ----- ABA 3 ----- */
function renderTabAgente(err){
  const p = document.getElementById("panelAgente");
  if(!Array.isArray(err.agent_flow.flow_steps)) err.agent_flow.flow_steps = [];
  if(err.agent_flow.start_step_id === undefined) err.agent_flow.start_step_id = null;
  const followup = err.agent_flow.post_fix_followup || { enabled:false, message:"" };
  err.agent_flow.post_fix_followup = followup;
  p.innerHTML = `
    <div class="hint" style="margin-bottom:18px;">
      Fluxo do bot: o cliente vê a lista de erros em aberto na plataforma → escolhe qual erro quer tratar →
      o agente faz as perguntas de validação abaixo → conforme as respostas, executa a ação correspondente
      sobre a(s) venda(s) afetada(s) → o cliente pode voltar depois para acompanhar o status dessas vendas.
    </div>
    <div class="agente-cols">
      <div class="agente-col-main">
        <div class="section-title">Fluxo de perguntas e ações</div>
        <div class="hint">Monte o fluxo como uma lista: cada etapa pode levar a outra etapa, a uma coleta de período, ou a uma mensagem final (que pode aplicar a correção nas vendas). Use <code>{{data_atual}}</code> em uma mensagem para exibir a data de hoje automaticamente.</div>
        <div class="diagram-legend" style="margin-top:8px;">
          <span class="lg-item"><span class="lg-dot" style="background:#7a1f6e;border-radius:50%;"></span> Ir para outra etapa</span>
          <span class="lg-item"><span class="lg-dot" style="background:#9a6512;border-radius:50%;"></span> Mensagem final</span>
          <span class="lg-item"><span class="lg-dot" style="background:#0f7a66;border-radius:50%;"></span> Corrigir vendas + mensagem</span>
        </div>
        <div class="field" style="max-width:360px;">
          <label>Etapa inicial do fluxo</label>
          <div id="a_start_step" class="custom-select-wrap"></div>
        </div>
        <div id="flowStepsList"></div>
        <button class="btn-ghost btn-sm" id="btnAddFlowStep">+ Adicionar etapa de pergunta</button>
        <button class="btn-ghost btn-sm" id="btnAddPeriodoStep">+ Adicionar etapa de período (calendário)</button>

        <div class="section-title">Condições de escalonamento</div>
        <div class="field">
          <p style="margin:0;font-size:13px;color:var(--text);background:var(--primary-light);border:1px solid #e7d3e2;border-radius:8px;padding:10px 14px;">As correções não foram possíveis ser aplicadas, deseja seguir com a abertura de um chamado para o nosso suporte técnico?</p>
        </div>
      </div>
      <div class="agente-col-preview">
        <div class="preview-card">
          <div class="section-title" style="margin-top:0;">Pré-visualização do fluxo</div>
          <div id="flowPreviewBox" class="system-prompt-box" style="font-family:inherit;white-space:normal;"></div>
          <button class="btn-teal btn-sm" id="btnSimulateBot" style="margin-top:10px;">🤖 Simular bot</button>
          <details style="margin-top:14px;">
            <summary style="cursor:pointer;font-size:12.5px;font-weight:600;color:var(--text-light);">Ver system prompt (avançado)</summary>
            <div class="system-prompt-box" id="systemPromptBox" style="margin-top:8px;"></div>
            <button class="btn-ghost btn-sm" id="btnCopyPrompt" style="margin-top:10px;">Copiar system prompt</button>
          </details>
        </div>
      </div>
    </div>
  `;
  document.getElementById("btnAddFlowStep").onclick = () => {
    const step = newFlowStep("question");
    err.agent_flow.flow_steps.push(step);
    if(!err.agent_flow.start_step_id) err.agent_flow.start_step_id = step.id;
    fieldChanged(); renderTabAgente(err);
  };
  document.getElementById("btnAddPeriodoStep").onclick = () => {
    const step = newFlowStep("periodo");
    err.agent_flow.flow_steps.push(step);
    if(!err.agent_flow.start_step_id) err.agent_flow.start_step_id = step.id;
    fieldChanged(); renderTabAgente(err);
  };
  document.getElementById("btnCopyPrompt").onclick = () => {
    navigator.clipboard.writeText(document.getElementById("systemPromptBox").textContent);
  };
  document.getElementById("btnSimulateBot").onclick = () => openBotSimulation(err);
  renderFlowSteps(err);
  updateSystemPrompt(err);
}

function newFlowStep(type){
  const id = "s_" + Math.random().toString(36).slice(2,9);
  if(type === "periodo"){
    return { id, type:"periodo", calendar_mode:"periodo", text:"", after:{ kind:null } };
  }
  return {
    id, type:"question", text:"", response_type:"sim_nao",
    options:[ { label:"Sim", after:{ kind:null } }, { label:"Não", after:{ kind:null } } ],
    after:{ kind:null }
  };
}

function stepNumber(err, stepId){
  const idx = err.agent_flow.flow_steps.findIndex(s => s.id === stepId);
  return idx === -1 ? "?" : (idx + 1);
}

function stepLabel(err, step){
  const t = htmlToText(step.text);
  const n = stepNumber(err, step.id);
  const preview = t ? (t.length > 40 ? t.slice(0,40)+"…" : t) : (step.type === "periodo" ? (step.calendar_mode === "data_unica" ? "(coleta de data única)" : "(coleta de período)") : "(sem texto)");
  return `Etapa ${n} — ${escapeHtml(preview)}`;
}

function renderStartStepSelect(err){
  const wrap = document.getElementById("a_start_step");
  if(!wrap) return;
  const steps = err.agent_flow.flow_steps;
  const options = [{value:"",label:"(nenhuma)"}].concat(
    steps.map(s => ({value:s.id,label:stepLabel(err, s)}))
  );
  renderCustomSelect(wrap, options, err.agent_flow.start_step_id || "", "(nenhuma)", value => {
    err.agent_flow.start_step_id = value || null;
    fieldChanged(); updateSystemPrompt(err);
  });
}

function closeAllCustomSelects(){
  document.querySelectorAll(".custom-select-wrap.open").forEach(w => w.classList.remove("open"));
}
document.addEventListener("click", e => {
  if(!e.target.closest(".custom-select-wrap")) closeAllCustomSelects();
});

function renderCustomSelect(wrap, options, value, placeholder, onChange){
  const selected = options.find(o => o.value === value) || options[0];
  wrap.innerHTML = `
    <div class="custom-select-trigger ${(!value || selected===options[0])?'placeholder-opt':''}">${selected ? selected.label : placeholder}</div>
    <div class="custom-select-dropdown">
      ${options.map(o => `<div class="custom-select-option ${o.value===''?'placeholder-opt':''} ${o.value===value?'selected':''}" data-value="${o.value}">${o.label}</div>`).join('')}
    </div>
  `;
  wrap.querySelector(".custom-select-trigger").onclick = e => {
    e.stopPropagation();
    const isOpen = wrap.classList.contains("open");
    closeAllCustomSelects();
    if(!isOpen) wrap.classList.add("open");
  };
  wrap.querySelectorAll(".custom-select-option").forEach(opt => {
    opt.onclick = e => {
      e.stopPropagation();
      closeAllCustomSelects();
      const newValue = opt.dataset.value;
      const trigger = wrap.querySelector(".custom-select-trigger");
      trigger.textContent = opt.textContent;
      trigger.classList.toggle("placeholder-opt", newValue === "" && opt.classList.contains("placeholder-opt"));
      wrap.querySelectorAll(".custom-select-option").forEach(o => o.classList.toggle("selected", o === opt));
      onChange(newValue);
    };
  });
}

function destPillLabel(after, err){
  const kind = after && after.kind;
  if(kind === "step"){
    const step = err.agent_flow.flow_steps.find(s => s.id === after.step_id);
    return step ? `→ ${stepLabel(err, step)}` : "→ etapa removida";
  }
  if(kind === "message") return "✓ Mensagem final";
  if(kind === "apply_correction") return "✓ Corrigir vendas + mensagem";
  return "⚠ Sem destino definido";
}
function destPillClass(after){
  const kind = after && after.kind;
  if(kind === "step") return "dest-step";
  if(kind === "message") return "dest-message";
  if(kind === "apply_correction") return "dest-apply_correction";
  return "dest-empty";
}

function renderAfterEditor(container, after, onChange, err, excludeStepId){
  container.innerHTML = `<button type="button" class="dest-pill ${destPillClass(after)}">${escapeHtml(destPillLabel(after, err))}</button>`;
  const pill = container.querySelector(".dest-pill");
  pill.onclick = () => {
    const existingPicker = container.querySelector(".dest-picker");
    if(existingPicker){ existingPicker.remove(); return; }
    document.querySelectorAll(".dest-picker").forEach(el => el.remove());
    const steps = err.agent_flow.flow_steps.filter(s => s.id !== excludeStepId);
    const picker = document.createElement("div");
    picker.className = "dest-picker";
    picker.innerHTML = `
      <button type="button" class="dest-opt" data-k="step">➜ Ir para outra etapa</button>
      <div class="dest-steps-area" style="display:none;margin:0 0 8px;">
        ${steps.map(s => `<span class="dest-step-chip" data-id="${s.id}">${escapeHtml(stepLabel(err,s))}</span>`).join('')}
        <span class="dest-step-chip" data-id="__new_question__">+ Nova pergunta</span>
        <span class="dest-step-chip" data-id="__new_periodo__">+ Novo período</span>
      </div>
      <button type="button" class="dest-opt" data-k="message">✓ Mensagem final</button>
      <button type="button" class="dest-opt" data-k="apply_correction">✓ Corrigir vendas + mensagem</button>
      <div class="dest-msg-area" style="display:none;">
        <textarea class="after-message" rows="2" placeholder="Mensagem... use {{data_atual}} para a data de hoje">${escapeHtml(after.text||"")}</textarea>
        <button type="button" class="btn-primary btn-sm dest-confirm">Confirmar</button>
      </div>
    `;
    container.appendChild(picker);
    const stepsArea = picker.querySelector(".dest-steps-area");
    const msgArea = picker.querySelector(".dest-msg-area");
    function closePicker(){ picker.remove(); }
    picker.querySelectorAll(".dest-opt").forEach(btn => {
      btn.onclick = () => {
        const k = btn.getAttribute("data-k");
        if(k === "step"){
          stepsArea.style.display = stepsArea.style.display === "none" ? "block" : "none";
          msgArea.style.display = "none";
        } else {
          msgArea.style.display = "block";
          msgArea.setAttribute("data-k", k);
          stepsArea.style.display = "none";
        }
      };
    });
    stepsArea.querySelectorAll(".dest-step-chip").forEach(chip => {
      chip.onclick = () => {
        const v = chip.getAttribute("data-id");
        if(v === "__new_question__" || v === "__new_periodo__"){
          const step = newFlowStep(v === "__new_periodo__" ? "periodo" : "question");
          err.agent_flow.flow_steps.push(step);
          onChange({ kind:"step", step_id: step.id });
          closePicker();
          fieldChanged(); updateSystemPrompt(err);
          setTimeout(() => { renderFlowSteps(err); highlightStep(step.id); }, 0);
          return;
        }
        onChange({ kind:"step", step_id: v });
        closePicker();
        fieldChanged(); updateSystemPrompt(err);
        setTimeout(() => renderFlowSteps(err), 0);
      };
    });
    picker.querySelector(".dest-confirm").onclick = () => {
      const k = msgArea.getAttribute("data-k");
      const text = picker.querySelector(".after-message").value;
      onChange({ kind:k, text });
      closePicker();
      fieldChanged(); updateSystemPrompt(err);
      setTimeout(() => renderFlowSteps(err), 0);
    };
  };
}

function buildStepCard(step, err){
  const block = document.createElement("div");
  block.className = "question-block";
  block.setAttribute("data-step-id", step.id);
  const typeLabel = step.type === "periodo" ? "Calendário" : "Pergunta";
  const markerColor = step.type === "periodo" ? "#2d6fd2" : "#7a1f6e";
  block.innerHTML = `
    <div class="top-row">
      <span style="display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:50%;background:${markerColor};color:#fff;font-size:11.5px;font-weight:700;flex:0 0 auto;">${stepNumber(err, step.id)}</span>
      <span class="hint" style="flex:1;text-transform:uppercase;font-size:11px;font-weight:700;letter-spacing:.02em;">${typeLabel}</span>
      <button class="rm" style="background:none;color:var(--danger);font-size:18px;">×</button>
    </div>
    <div class="rich-editor" style="margin-top:8px;"></div>
    <div class="step-body" style="margin-top:8px;"></div>
  `;
  block.querySelector(".rm").onclick = () => {
    removeStepAndReferences(err, step.id);
    fieldChanged(); renderTabAgente(err);
  };
  mountRichEditor(block.querySelector(".rich-editor"), step.text, step.type === "periodo" ? "Texto introdutório (opcional)..." : "Texto da pergunta...", html => {
    step.text = html; fieldChanged(); updateSystemPrompt(err); renderStartStepSelect(err);
  });

  const body = block.querySelector(".step-body");
  if(step.type === "periodo"){
    if(!step.calendar_mode) step.calendar_mode = "periodo";
    const modeRow = document.createElement("div");
    modeRow.style.marginBottom = "8px";
    modeRow.innerHTML = `
      <label class="hint" style="display:block;margin-bottom:4px;">Modo do calendário:</label>
      <label style="margin-right:16px;cursor:pointer;font-size:13px;">
        <input type="radio" name="calmode_${step.id}" value="periodo" ${step.calendar_mode==="periodo"?"checked":""} style="margin-right:4px;">Período (início e fim)
      </label>
      <label style="cursor:pointer;font-size:13px;">
        <input type="radio" name="calmode_${step.id}" value="data_unica" ${step.calendar_mode==="data_unica"?"checked":""} style="margin-right:4px;">Data única
      </label>
    `;
    modeRow.querySelectorAll("input[type=radio]").forEach(r => {
      r.onchange = e => { step.calendar_mode = e.target.value; afterLabel.textContent = calAfterLabel(step); fieldChanged(); updateSystemPrompt(err); };
    });
    body.appendChild(modeRow);
    const afterWrap = document.createElement("div");
    const calAfterLabel = s => s.calendar_mode === "data_unica" ? "Depois de coletar a data:" : "Depois de coletar início e fim do período:";
    const afterLabel = document.createElement("label");
    afterLabel.className = "hint";
    afterLabel.textContent = calAfterLabel(step);
    afterWrap.appendChild(afterLabel);
    const afterEditor = document.createElement("div");
    afterWrap.appendChild(afterEditor);
    body.appendChild(afterWrap);
    renderAfterEditor(afterEditor, step.after, next => { step.after = next; fieldChanged(); updateSystemPrompt(err); }, err, step.id);
  } else {
    const typeRow = document.createElement("div");
    typeRow.style.marginBottom = "8px";
    typeRow.innerHTML = `
      <select class="response-type-select" style="width:160px;">
        <option value="sim_nao" ${step.response_type==='sim_nao'?'selected':''}>Sim/Não</option>
        <option value="texto_livre" ${step.response_type==='texto_livre'?'selected':''}>Texto livre</option>
        <option value="multipla_escolha" ${step.response_type==='multipla_escolha'?'selected':''}>Múltipla escolha</option>
      </select>
    `;
    body.appendChild(typeRow);
    const select = typeRow.querySelector(".response-type-select");
    select.onchange = e => {
      const prevType = step.response_type;
      step.response_type = e.target.value;
      if(step.response_type === "sim_nao"){
        step.options = [ { label:"Sim", after:{ kind:null } }, { label:"Não", after:{ kind:null } } ];
      } else if(step.response_type === "multipla_escolha"){
        step.options = prevType === "multipla_escolha" && step.options ? step.options : [];
      } else {
        step.options = null;
        step.after = step.after || { kind:null };
      }
      fieldChanged(); updateSystemPrompt(err);
      setTimeout(() => renderFlowSteps(err), 0);
    };

    if(step.response_type === "sim_nao" || step.response_type === "multipla_escolha"){
      const optsWrap = document.createElement("div");
      body.appendChild(optsWrap);
      (step.options||[]).forEach((opt, oi) => {
        const optRow = document.createElement("div");
        optRow.className = "branch-row";
        const labelEl = document.createElement("span");
        labelEl.className = "branch-opt-label";
        if(step.response_type === "multipla_escolha"){
          labelEl.innerHTML = `<input type="text" value="${escapeAttr(opt.label)}" placeholder="Texto da opção" style="width:160px;"><button class="rm-opt" style="background:none;color:var(--danger);font-size:16px;vertical-align:middle;">×</button>`;
          labelEl.querySelector("input").oninput = e => { opt.label = e.target.value; fieldChanged(); updateSystemPrompt(err); renderStartStepSelect(err); };
          labelEl.querySelector(".rm-opt").onclick = () => { step.options.splice(oi,1); fieldChanged(); renderFlowSteps(err); };
        } else {
          labelEl.innerHTML = `<strong>${escapeHtml(opt.label)}</strong>`;
        }
        optRow.appendChild(labelEl);
        const afterEditor = document.createElement("div");
        optRow.appendChild(afterEditor);
        renderAfterEditor(afterEditor, opt.after, next => { opt.after = next; fieldChanged(); updateSystemPrompt(err); }, err, step.id);
        optsWrap.appendChild(optRow);
      });
      if(step.response_type === "multipla_escolha"){
        const addRow = document.createElement("div");
        addRow.innerHTML = `<input type="text" placeholder="Nova opção e Enter" style="width:220px;">`;
        const addInput = addRow.querySelector("input");
        addInput.onkeydown = e => {
          if(e.key === "Enter" && addInput.value.trim()){
            step.options = step.options || [];
            step.options.push({ label:addInput.value.trim(), after:{ kind:null } });
            fieldChanged(); renderFlowSteps(err);
          }
        };
        body.appendChild(addRow);
      }
    } else {
      const afterWrap = document.createElement("div");
      afterWrap.innerHTML = `<label class="hint">Depois de receber a resposta em texto livre:</label>`;
      const afterEditor = document.createElement("div");
      afterWrap.appendChild(afterEditor);
      body.appendChild(afterWrap);
      step.after = step.after || { kind:null };
      renderAfterEditor(afterEditor, step.after, next => { step.after = next; fieldChanged(); updateSystemPrompt(err); }, err, step.id);
    }
  }
  return block;
}

function highlightStep(stepId){
  const el = document.querySelector(`#flowStepsList [data-step-id="${stepId}"]`);
  if(!el) return;
  el.scrollIntoView({ behavior:"smooth", block:"center" });
  el.classList.add("flow-highlight");
  setTimeout(() => el.classList.remove("flow-highlight"), 1200);
  const titleField = el.querySelector(".rich-editor .rt-content");
  if(titleField) titleField.focus();
}

function stepBranchTargets(step){
  if(step.type === "periodo") return [{ key:"main", label:null, after: step.after }];
  if(step.response_type === "texto_livre") return [{ key:"main", label:null, after: step.after }];
  return (step.options||[]).map((opt, oi) => ({ key:String(oi), label: opt.label, after: opt.after }));
}

function removeStepAndReferences(err, stepId){
  const ef = err.agent_flow;
  const idx = ef.flow_steps.findIndex(s => s.id === stepId);
  if(idx === -1) return;
  ef.flow_steps.splice(idx,1);
  if(ef.start_step_id === stepId) ef.start_step_id = ef.flow_steps[0] ? ef.flow_steps[0].id : null;
  ef.flow_steps.forEach(s => {
    stepBranchTargets(s).forEach(b => {
      if(b.after && b.after.kind === "step" && b.after.step_id === stepId){
        b.after.kind = null;
        delete b.after.step_id;
      }
    });
  });
  if(ef.diagram_positions) delete ef.diagram_positions[stepId];
}

function renderFlowSteps(err){
  renderStartStepSelect(err);
  const list = document.getElementById("flowStepsList");
  list.innerHTML = "";
  err.agent_flow.flow_steps.forEach(step => {
    list.appendChild(buildStepCard(step, err));
  });
}

/* ----- ABA 4: DIAGRAMA VISUAL ----- */
function diagramLayout(err){
  const ef = err.agent_flow;
  const positions = ef.diagram_positions = ef.diagram_positions || {};
  const termPositions = ef.diagram_term_positions = ef.diagram_term_positions || {};
  const depth = {};
  const order = [];
  const visited = new Set();
  if(ef.start_step_id){
    const queue = [[ef.start_step_id, 0]];
    while(queue.length){
      const [id, d] = queue.shift();
      if(visited.has(id)) continue;
      visited.add(id);
      depth[id] = d;
      order.push(id);
      const step = ef.flow_steps.find(s => s.id === id);
      if(!step) continue;
      stepBranchTargets(step).forEach(b => {
        if(b.after && b.after.kind === "step" && b.after.step_id && !visited.has(b.after.step_id)){
          queue.push([b.after.step_id, d+1]);
        }
      });
    }
  }
  const maxDepth = order.length ? Math.max(...order.map(id => depth[id])) : -1;
  ef.flow_steps.forEach(s => {
    if(!visited.has(s.id)){
      depth[s.id] = maxDepth + 1;
      order.push(s.id);
      visited.add(s.id);
    }
  });
  const colCount = {};
  order.forEach(id => {
    const d = depth[id] || 0;
    const row = colCount[d] || 0;
    colCount[d] = row + 1;
    if(!positions[id]) positions[id] = { x: 40 + d*260, y: 40 + row*150 };
  });
  ef.flow_steps.forEach(step => {
    stepBranchTargets(step).forEach(branch => {
      if(!branch.after || (branch.after.kind !== "message" && branch.after.kind !== "apply_correction")) return;
      const key = step.id + "::" + branch.key;
      const d = (depth[step.id] || 0) + 1;
      const row = colCount[d] || 0;
      colCount[d] = row + 1;
      if(!termPositions[key]) termPositions[key] = { x: 40 + d*260, y: 40 + row*150 };
    });
  });
  return { positions, termPositions, depth };
}

function autoLayoutDiagram(err){
  /* Layout de árvore vertical (Reingold-Tilford simplificado):
     - Folhas (terminais e steps sem filhos) recebem colunas sequenciais da esquerda
     - Nós internos se centralizam horizontalmente sobre os filhos
     - Profundidade determina o Y → linhas ficam quase verticais, sem cruzamentos */
  const ef = err.agent_flow;
  ef.diagram_positions = {};
  ef.diagram_term_positions = {};
  const positions = ef.diagram_positions;
  const termPositions = ef.diagram_term_positions;

  const COL_W = 290;  // largura de uma coluna (box + gap)
  const ROW_H = 220;  // altura de uma linha (box + gap)
  const START_X = 40;
  const START_Y = 40;

  let leafIdx = 0;
  const nodeCol = {};   // stepId | termKey → coluna (float, pode ser .5)
  const nodeRow = {};   // stepId | termKey → linha (int)

  function processStep(stepId, row, visited){
    if(visited.has(stepId)){
      // ciclo: tratar como folha se ainda não posicionado
      if(nodeCol[stepId] === undefined){ nodeCol[stepId] = leafIdx++; nodeRow[stepId] = row; }
      return nodeCol[stepId];
    }
    const v = new Set(visited); v.add(stepId);
    nodeRow[stepId] = row;

    const step = ef.flow_steps.find(s => s.id === stepId);
    if(!step){ nodeCol[stepId] = leafIdx++; return nodeCol[stepId]; }

    const branches = stepBranchTargets(step);
    const childCols = [];

    branches.forEach(b => {
      if(!b.after || !b.after.kind) return; // sem destino — ignora
      if(b.after.kind === "step" && b.after.step_id){
        childCols.push(processStep(b.after.step_id, row + 1, v));
      } else if(b.after.kind === "message" || b.after.kind === "apply_correction"){
        const key = stepId + "::" + b.key;
        nodeRow[key] = row + 1;
        nodeCol[key] = leafIdx++;
        childCols.push(nodeCol[key]);
      }
    });

    // se não há filhos conectados → folha
    if(!childCols.length){ nodeCol[stepId] = leafIdx++; return nodeCol[stepId]; }

    // centrar acima dos filhos
    nodeCol[stepId] = (Math.min(...childCols) + Math.max(...childCols)) / 2;
    return nodeCol[stepId];
  }

  if(ef.start_step_id) processStep(ef.start_step_id, 0, new Set());

  // Orphans (steps não alcançados pelo start)
  ef.flow_steps.forEach(step => {
    if(nodeCol[step.id] === undefined){ nodeCol[step.id] = leafIdx++; nodeRow[step.id] = 0; }
  });

  // Converter col/row → pixels
  ef.flow_steps.forEach(step => {
    if(nodeCol[step.id] !== undefined){
      positions[step.id] = {
        x: Math.round(START_X + nodeCol[step.id] * COL_W),
        y: Math.round(START_Y + (nodeRow[step.id] || 0) * ROW_H)
      };
    }
  });
  Object.keys(nodeCol).forEach(key => {
    if(!key.includes("::")) return;
    termPositions[key] = {
      x: Math.round(START_X + nodeCol[key] * COL_W),
      y: Math.round(START_Y + (nodeRow[key] || 0) * ROW_H)
    };
  });
}

function diagramBranchIcon(step){
  if(step.type === "periodo") return "📅";
  if(step.response_type === "texto_livre") return "✏️";
  if(step.response_type === "sim_nao") return "❓";
  return "☰";
}

function diagramAfterSummary(after){
  if(!after || !after.kind) return "(sem destino)";
  if(after.kind === "step") return null;
  return null;
}

function renderTabDiagrama(err){
  const p = document.getElementById("panelDiagrama");
  if(!p) return;
  if(window.__diagramDisarmPort) window.__diagramDisarmPort();
  const ef = err.agent_flow;
  const { positions, termPositions } = diagramLayout(err);
  let popover = null;
  function closePopover(){ if(popover){ popover.remove(); popover = null; } }

  const allX = ef.flow_steps.map(s => (positions[s.id]?.x||0) + 260).concat(Object.values(termPositions).map(t => t.x + 240));
  const allY = ef.flow_steps.map(s => (positions[s.id]?.y||0) + 220).concat(Object.values(termPositions).map(t => t.y + 160));
  const maxX = allX.length ? Math.max(...allX) : 600;
  const maxY = allY.length ? Math.max(...allY) : 400;

  p.innerHTML = `
    <div class="hint" style="margin-bottom:10px;">Arraste as caixas para reorganizar. Para ligar um destino: arraste a bolinha de saída até a etapa desejada (ela fica destacada enquanto você arrasta), ou clique na bolinha uma vez para "armar" a conexão e depois clique na etapa de destino (Esc cancela; clique na bolinha de novo para escolher "mensagem final"/"aplicar correção"). Use ✎ para editar o texto na aba 3, × para excluir.</div>
    <div class="diagram-legend">
      <span class="lg-item"><span class="lg-dot" style="background:#7a1f6e;"></span> Pergunta</span>
      <span class="lg-item"><span class="lg-dot" style="background:#2560b8;"></span> Período</span>
      <span class="lg-item"><span class="lg-dot" style="background:#9a6512;"></span> Mensagem final</span>
      <span class="lg-item"><span class="lg-dot" style="background:#0f7a66;"></span> Corrigir vendas</span>
    </div>
    <button class="btn-ghost btn-sm" id="btnDiagAddQuestion">+ Pergunta</button>
    <button class="btn-ghost btn-sm" id="btnDiagAddPeriodo" style="margin-left:6px;">+ Período (calendário)</button>
    <button class="btn-ghost btn-sm" id="btnDiagAutoLayout" style="margin-left:16px;border-color:var(--teal);color:var(--teal);" title="Reorganiza automaticamente todas as caixas">⟳ Reorganizar layout</button>
    <div id="diagramCanvasWrap" style="position:relative;overflow:auto;border:1px solid var(--border);border-radius:8px;margin-top:10px;height:600px;background-color:var(--bg-soft);background-image:radial-gradient(circle,#d8dee2 1px,transparent 1px);background-size:18px 18px;">
      <div id="diagramCanvas" style="position:relative;width:${maxX+260}px;height:${maxY+200}px;">
        <svg id="diagramSvg" style="position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;overflow:visible;z-index:10;">
          <defs>
            <marker id="diagArrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
              <path d="M0,0 L6,3 L0,6 Z" fill="var(--teal,#0a8a7d)"></path>
            </marker>
          </defs>
        </svg>
      </div>
    </div>
  `;

  const wrap = document.getElementById("diagramCanvasWrap");
  const canvas = document.getElementById("diagramCanvas");
  const svg = document.getElementById("diagramSvg");

  function portEl(stepId, branchKey){
    return canvas.querySelector(`.diagram-port[data-step-id="${stepId}"][data-branch-key="${branchKey}"]`);
  }
  function boxEl(stepId){
    return canvas.querySelector(`.diagram-box[data-step-id="${stepId}"]`);
  }
  function termEl(stepId, branchKey){
    return canvas.querySelector(`.diagram-term[data-step-id="${stepId}"][data-branch-key="${branchKey}"]`);
  }
  function centerOf(el, parent){
    const r = el.getBoundingClientRect();
    const pr = parent.getBoundingClientRect();
    return { x: r.left - pr.left + r.width/2, y: r.top - pr.top + r.height/2 };
  }
  function anchorRatioFor(boxEl, clientY){
    const r = boxEl.getBoundingClientRect();
    if(r.height <= 0) return 0.5;
    const ratio = (clientY - r.top) / r.height;
    return Math.min(0.9, Math.max(0.1, ratio));
  }
  function pickEdgeAndRatio(p1, r, dropX, dropY){
    const dxOut = Math.max(r.left - p1.x, p1.x - r.right, 0);
    const dyOut = Math.max(r.top - p1.y, p1.y - r.bottom, 0);
    let edge;
    if(dyOut > dxOut){
      edge = p1.y < r.top ? "top" : "bottom";
    } else {
      edge = p1.x < r.left ? "left" : "right";
    }
    let ratio;
    if(edge === "top" || edge === "bottom"){
      ratio = r.width > 0 ? (dropX - r.left) / r.width : 0.5;
    } else {
      ratio = r.height > 0 ? (dropY - r.top) / r.height : 0.5;
    }
    return { edge, ratio: Math.min(0.9, Math.max(0.1, ratio)) };
  }
  function pointForEdge(edge, ratio, r){
    switch(edge){
      case "top": return { x: r.left + r.width * ratio, y: r.top };
      case "bottom": return { x: r.left + r.width * ratio, y: r.bottom };
      case "left": return { x: r.left, y: r.top + r.height * ratio };
      default: return { x: r.right, y: r.top + r.height * ratio };
    }
  }
  function rectOf(el){
    const r = el.getBoundingClientRect();
    const pr = canvas.getBoundingClientRect();
    return { left: r.left - pr.left, right: r.right - pr.left, top: r.top - pr.top, bottom: r.bottom - pr.top, width: r.width, height: r.height };
  }
  function splitLineByObstacles(p1, p2, obstacles){
    const pad = 6;
    const steps = 120;
    const isInside = pt => obstacles.some(r => pt.x > r.left+pad && pt.x < r.right-pad && pt.y > r.top+pad && pt.y < r.bottom-pad);
    const clear = [], over = [];
    let runStart = p1, runInside = isInside(p1);
    let prev = p1;
    for(let i = 1; i <= steps; i++){
      const t = i / steps;
      const pt = { x: p1.x + (p2.x - p1.x) * t, y: p1.y + (p2.y - p1.y) * t };
      const inside = isInside(pt);
      if(inside !== runInside){
        (runInside ? over : clear).push([runStart, prev]);
        runStart = prev;
        runInside = inside;
      }
      prev = pt;
    }
    (runInside ? over : clear).push([runStart, p2]);
    return { clear, over };
  }
  function bezierPoint(p1, c1, c2, p2, t){
    const u = 1 - t;
    return {
      x: u*u*u*p1.x + 3*u*u*t*c1.x + 3*u*t*t*c2.x + t*t*t*p2.x,
      y: u*u*u*p1.y + 3*u*u*t*c1.y + 3*u*t*t*c2.y + t*t*t*p2.y
    };
  }
  function findObstacleRect(p1, c1, c2, p2, obstacles, sourceRect){
    const pad = 6;
    const nearPort = 16;
    const inside = (pt, r, p) => pt.x > r.left+p && pt.x < r.right-p && pt.y > r.top+p && pt.y < r.bottom-p;
    for(let i = 1; i < 24; i++){
      const pt = bezierPoint(p1, c1, c2, p2, i/24);
      for(const r of obstacles){
        if(inside(pt, r, pad)) return r;
      }
      if(sourceRect){
        const dist = Math.hypot(pt.x - p1.x, pt.y - p1.y);
        if(dist > nearPort && inside(pt, sourceRect, pad)) return sourceRect;
      }
    }
    return null;
  }
  function buildDetourPoints(p1, p2, edge, obstacle){
    const margin = 20;
    function chooseSide(a, b, lo, hi){
      const left = lo - margin, right = hi + margin;
      const costLeft = Math.abs(a-left) + Math.abs(b-left);
      const costRight = Math.abs(a-right) + Math.abs(b-right);
      return costLeft <= costRight ? left : right;
    }
    const stub = 16;
    const clear = 4;
    if(edge === "top" || edge === "bottom"){
      const sideX = chooseSide(p1.x, p2.x, obstacle.left, obstacle.right);
      let approachY;
      if(edge === "top"){
        const desired = p2.y - stub;
        approachY = obstacle.bottom > desired ? Math.min(p2.y - 2, obstacle.bottom + clear) : desired;
      } else {
        const desired = p2.y + stub;
        approachY = obstacle.top < desired ? Math.max(p2.y + 2, obstacle.top - clear) : desired;
      }
      return [p1, {x:sideX,y:p1.y}, {x:sideX,y:approachY}, {x:p2.x,y:approachY}, p2];
    }
    const sideY = chooseSide(p1.y, p2.y, obstacle.top, obstacle.bottom);
    let approachX;
    if(edge === "left"){
      const desired = p2.x - stub;
      approachX = obstacle.right > desired ? Math.min(p2.x - 2, obstacle.right + clear) : desired;
    } else {
      const desired = p2.x + stub;
      approachX = obstacle.left < desired ? Math.max(p2.x + 2, obstacle.left - clear) : desired;
    }
    return [p1, {x:p1.x,y:sideY}, {x:approachX,y:sideY}, {x:approachX,y:p2.y}, p2];
  }

  function drawArrow(p1, p2, label, color, onDelete, p2Edge, sourceBoxEl, targetBoxEl){
    const midX = (p1.x + p2.x) / 2;
    const midY = (p1.y + p2.y) / 2;
    const vertical = p2Edge === "top" || p2Edge === "bottom";
    const c1 = { x: midX, y: p1.y };
    const c2 = vertical ? { x: p2.x, y: midY } : { x: midX, y: p2.y };
    const stroke = color || "var(--teal,#0a8a7d)";
    const obstacles = [...canvas.querySelectorAll(".diagram-box, .diagram-term")]
      .filter(el => el !== sourceBoxEl)
      .map(rectOf);
    const sourceRect = sourceBoxEl ? rectOf(sourceBoxEl) : null;
    const obstacle = findObstacleRect(p1, c1, c2, p2, obstacles, sourceRect);
    let d, hitD, labelX = midX, labelY = midY;
    if(obstacle){
      const pts = buildDetourPoints(p1, p2, p2Edge, obstacle);
      d = "M " + pts.map(pt => `${pt.x} ${pt.y}`).join(" L ");
      const mid = pts[Math.floor(pts.length/2)];
      labelX = mid.x; labelY = mid.y;
      if(onDelete){
        const trim = 16;
        const a = pts[0], b = pts[1];
        const distAB = Math.hypot(b.x-a.x, b.y-a.y) || 1;
        const ta = Math.min(trim, distAB) / distAB;
        const p1t = { x: a.x + (b.x-a.x)*ta, y: a.y + (b.y-a.y)*ta };
        const lastIdx = pts.length - 1;
        const c = pts[lastIdx-1], e = pts[lastIdx];
        const distCE = Math.hypot(e.x-c.x, e.y-c.y) || 1;
        const tb = Math.min(trim, distCE) / distCE;
        const p2t = { x: e.x + (c.x-e.x)*tb, y: e.y + (c.y-e.y)*tb };
        const trimmedPts = [p1t, ...pts.slice(1, lastIdx), p2t];
        hitD = "M " + trimmedPts.map(pt => `${pt.x} ${pt.y}`).join(" L ");
      }
    } else {
      d = `M ${p1.x} ${p1.y} C ${c1.x} ${c1.y}, ${c2.x} ${c2.y}, ${p2.x} ${p2.y}`;
      if(onDelete){
        const trim = 16;
        const p1t = { x: p1.x + Math.sign(c1.x - p1.x) * Math.min(trim, Math.abs(c1.x - p1.x)), y: p1.y };
        const p2t = vertical
          ? { x: p2.x, y: p2.y - Math.sign(p2.y - c2.y) * Math.min(trim, Math.abs(p2.y - c2.y)) }
          : { x: p2.x - Math.sign(p2.x - c2.x) * Math.min(trim, Math.abs(p2.x - c2.x)), y: p2.y };
        hitD = `M ${p1t.x} ${p1t.y} C ${c1.x} ${p1t.y}, ${vertical ? p2t.x : c2.x} ${vertical ? c2.y : p2t.y}, ${p2t.x} ${p2t.y}`;
      }
    }
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", d);
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", stroke);
    path.setAttribute("stroke-width", "2");
    path.setAttribute("marker-end", "url(#diagArrow)");
    path.setAttribute("class", "diagram-line-visible");
    svg.appendChild(path);
    if(onDelete && hitD){
      const hit = document.createElementNS("http://www.w3.org/2000/svg", "path");
      hit.setAttribute("d", hitD);
      hit.setAttribute("fill", "none");
      hit.setAttribute("stroke", "transparent");
      hit.setAttribute("stroke-width", "14");
      hit.setAttribute("class", "diagram-line-hit");
      hit.addEventListener("mouseenter", () => path.setAttribute("stroke-width", "3.5"));
      hit.addEventListener("mouseleave", () => path.setAttribute("stroke-width", "2"));
      hit.addEventListener("click", e => {
        e.preventDefault(); e.stopPropagation();
        onDelete();
      });
      const titleEl = document.createElementNS("http://www.w3.org/2000/svg", "title");
      titleEl.textContent = "Clique para apagar esta conexão";
      hit.appendChild(titleEl);
      svg.appendChild(hit);
    }
    if(label){
      const width = Math.min(220, Math.max(56, label.length * 6.4 + 26));
      const fo = document.createElementNS("http://www.w3.org/2000/svg", "foreignObject");
      fo.setAttribute("x", labelX - width/2);
      fo.setAttribute("y", labelY - 11);
      fo.setAttribute("width", width);
      fo.setAttribute("height", 22);
      fo.innerHTML = `<div xmlns="http://www.w3.org/1999/xhtml" style="text-align:center;overflow:visible;"><span style="display:inline-block;max-width:${width-4}px;overflow:hidden;text-overflow:ellipsis;background:#fff;border:1px solid ${stroke};color:${stroke};font-size:10.5px;font-weight:600;padding:2px 6px;border-radius:999px;white-space:nowrap;box-sizing:border-box;">${escapeHtml(label)}</span></div>`;
      svg.appendChild(fo);
    }
  }

  function redrawLines(){
    while(svg.children.length > 1) svg.removeChild(svg.lastChild);
    ef.flow_steps.forEach(step => {
      stepBranchTargets(step).forEach(branch => {
        if(!branch.after || !branch.after.kind) return;
        const port = portEl(step.id, branch.key);
        if(!port) return;
        const p1 = centerOf(port, canvas);
        let target = null;
        if(branch.after.kind === "step" && branch.after.step_id) target = boxEl(branch.after.step_id);
        else if(branch.after.kind === "message" || branch.after.kind === "apply_correction") target = termEl(step.id, branch.key);
        if(!target) return;
        const tr = target.getBoundingClientRect();
        const pr = canvas.getBoundingClientRect();
        const r = { left: tr.left - pr.left, right: tr.right - pr.left, top: tr.top - pr.top, bottom: tr.bottom - pr.top, width: tr.width, height: tr.height };
        const anchorRatio = typeof branch.after.target_anchor === "number" ? branch.after.target_anchor : 0.5;
        const { edge } = pickEdgeAndRatio(p1, r, p1.x, p1.y);
        const p2 = pointForEdge(edge, anchorRatio, r);
        const color = branch.after.kind === "message" ? "#9a6512" : branch.after.kind === "apply_correction" ? "#0f7a66" : "#7a1f6e";
        drawArrow(p1, p2, branch.label, color, () => {
          if(!confirm("Apagar esta conexão? Você poderá arrastar a bolinha novamente para refazer.")) return;
          setBranchAfter(branch, {});
          renderTabDiagrama(err);
        }, edge, boxEl(step.id), target);
      });
    });
  }

  function setBranchAfter(branch, next){
    branch.after.kind = next.kind || null;
    if(next.kind === "step"){
      branch.after.step_id = next.step_id;
      delete branch.after.text;
      if(typeof next.target_anchor === "number") branch.after.target_anchor = next.target_anchor;
      else delete branch.after.target_anchor;
    }
    else if(next.kind === "message" || next.kind === "apply_correction"){ branch.after.text = next.text || branch.after.text || ""; delete branch.after.step_id; delete branch.after.target_anchor; }
    else { delete branch.after.step_id; delete branch.after.text; delete branch.after.target_anchor; }
    fieldChanged(); updateSystemPrompt(err);
  }

  let highlightedBox = null;
  function clearDropHighlight(){
    if(highlightedBox){ highlightedBox.classList.remove("diagram-drop-valid","diagram-drop-invalid"); highlightedBox = null; }
  }
  function setDropHighlight(box, valid){
    if(box === highlightedBox) return;
    clearDropHighlight();
    if(box){ box.classList.add(valid ? "diagram-drop-valid" : "diagram-drop-invalid"); highlightedBox = box; }
  }
  function candidateBoxAt(clientX, clientY){
    const boxes = canvas.querySelectorAll(".diagram-box");
    for(let i = boxes.length - 1; i >= 0; i--){
      const box = boxes[i];
      const r = box.getBoundingClientRect();
      if(clientX >= r.left && clientX <= r.right && clientY >= r.top && clientY <= r.bottom) return box;
    }
    return null;
  }

  let armedPort = null;
  let connectHint = null;
  function removeConnectHint(){ if(connectHint){ connectHint.remove(); connectHint = null; } }
  function showConnectHint(anchorEl, text){
    removeConnectHint();
    const r = anchorEl.getBoundingClientRect();
    const pr = canvas.getBoundingClientRect();
    connectHint = document.createElement("div");
    connectHint.className = "diagram-connect-hint";
    connectHint.textContent = text;
    connectHint.style.left = (r.left - pr.left + 16) + "px";
    connectHint.style.top = (r.top - pr.top - 28) + "px";
    canvas.appendChild(connectHint);
  }
  function onKeyForConnect(e){ if(e.key === "Escape") disarmPort(); }
  function onDocClickForConnect(e){
    if(!armedPort) return;
    const branch = armedPort.branch, portEl = armedPort.portEl;
    if(e.target === portEl){
      e.preventDefault(); e.stopPropagation();
      disarmPort();
      openPortPopover(branch, portEl);
      return;
    }
    if(e.target.closest("button")){ disarmPort(); return; }
    const targetBox = e.target.closest(".diagram-box") || candidateBoxAt(e.clientX, e.clientY);
    if(targetBox && targetBox.classList.contains("diagram-term")){ disarmPort(); return; }
    if(targetBox && targetBox.getAttribute("data-step-id") !== branch.ownerStepId){
      e.preventDefault(); e.stopPropagation();
      const pr2 = canvas.getBoundingClientRect();
      const p1 = centerOf(portEl, canvas);
      const tr0 = targetBox.getBoundingClientRect();
      const tr = { left: tr0.left - pr2.left, right: tr0.right - pr2.left, top: tr0.top - pr2.top, bottom: tr0.bottom - pr2.top, width: tr0.width, height: tr0.height };
      const { edge, ratio: anchor } = pickEdgeAndRatio(p1, tr, e.clientX - pr2.left, e.clientY - pr2.top);
      setBranchAfter(branch, { kind:"step", step_id: targetBox.getAttribute("data-step-id"), target_anchor: anchor });
      disarmPort();
      renderTabDiagrama(err);
      return;
    }
    disarmPort();
  }
  function disarmPort(){
    if(armedPort){ armedPort.portEl.classList.remove("diagram-port-armed"); armedPort = null; }
    removeConnectHint();
    document.removeEventListener("click", onDocClickForConnect, true);
    document.removeEventListener("keydown", onKeyForConnect, true);
  }
  window.__diagramDisarmPort = disarmPort;
  function armPort(branch, portEl){
    disarmPort();
    armedPort = { branch, portEl };
    portEl.classList.add("diagram-port-armed");
    showConnectHint(portEl, "Clique na etapa de destino (Esc cancela, clique aqui de novo p/ opções)");
    setTimeout(() => {
      if(armedPort && armedPort.portEl === portEl){
        document.addEventListener("click", onDocClickForConnect, true);
        document.addEventListener("keydown", onKeyForConnect, true);
      }
    }, 0);
  }

  function openPortPopover(branch, anchorEl){
    closePopover();
    const r = anchorEl.getBoundingClientRect();
    const pr = canvas.getBoundingClientRect();
    popover = document.createElement("div");
    popover.className = "diagram-port-popover";
    popover.style.left = (r.left - pr.left + 16) + "px";
    popover.style.top = (r.top - pr.top + 16) + "px";
    const editorWrap = document.createElement("div");
    popover.appendChild(editorWrap);
    const closeBtn = document.createElement("button");
    closeBtn.className = "btn-ghost btn-sm";
    closeBtn.textContent = "Fechar";
    closeBtn.style.marginTop = "8px";
    closeBtn.onclick = () => closePopover();
    popover.appendChild(closeBtn);
    canvas.appendChild(popover);
    const stepsCountBefore = ef.flow_steps.length;
    const kindBefore = branch.after.kind;
    renderAfterEditor(editorWrap, branch.after, next => {
      setBranchAfter(branch, next);
      const structuralChange = (next.kind === "step" && ef.flow_steps.length !== stepsCountBefore) ||
        (next.kind !== kindBefore && (next.kind === "message" || next.kind === "apply_correction" || kindBefore === "message" || kindBefore === "apply_correction"));
      if(structuralChange){
        closePopover();
        setTimeout(() => renderTabDiagrama(err), 0);
        return;
      }
      redrawLines();
      refreshBranchRow(branch);
    }, err, branch.ownerStepId);
  }

  function refreshBranchRow(branch){
    const row = canvas.querySelector(`.diagram-branch-row[data-step-id="${branch.ownerStepId}"][data-branch-key="${branch.key}"]`);
    if(!row) return;
    const label = row.querySelector(".db-label");
    if(!label) return;
    const step = ef.flow_steps.find(s => s.id === branch.ownerStepId);
    const summary = diagramAfterSummary(branch.after);
    const labelText = branch.label ? branch.label : (step.type === "periodo" ? "após período" : "após resposta");
    label.textContent = labelText + (summary ? " — " + summary : "");
    const port = row.querySelector(".diagram-port");
    if(port){
      const isEmpty = !branch.after || !branch.after.kind;
      port.className = isEmpty ? "diagram-port diagram-port-empty" : "diagram-port";
      port.textContent = isEmpty ? "+ ligar" : "";
    }
    const term = termEl(branch.ownerStepId, branch.key);
    if(term) term.querySelector(".db-body").textContent = htmlToText(branch.after.text) || "(sem texto)";
  }

  function makeTermBox(step, branch){
    const pos = termPositions[step.id + "::" + branch.key] || { x:40, y:40 };
    const box = document.createElement("div");
    box.className = "diagram-box diagram-term diagram-term-" + (branch.after.kind === "apply_correction" ? "correction" : "message");
    box.setAttribute("data-step-id", step.id);
    box.setAttribute("data-branch-key", branch.key);
    box.style.left = pos.x + "px";
    box.style.top = pos.y + "px";
    box.style.borderStyle = "dashed";
    const icon = branch.after.kind === "apply_correction" ? "✅" : "💬";
    const text = htmlToText(branch.after.text);
    box.innerHTML = `
      <div class="db-head">
        <span>${icon} Fim</span>
      </div>
      <div class="db-body">${escapeHtml(text || "(sem texto)")}</div>
    `;
    box.addEventListener("click", e => {
      if(e.target.closest("button")) return;
      openPortPopover(branch, box);
    });
    box.addEventListener("mousedown", e => {
      e.stopPropagation();
      box.classList.add("dragging");
      const startX = e.clientX, startY = e.clientY;
      const startLeft = pos.x, startTop = pos.y;
      let moved = false;
      function onMove(ev){
        if(Math.abs(ev.clientX-startX) > 4 || Math.abs(ev.clientY-startY) > 4) moved = true;
        const nx = Math.max(0, startLeft + (ev.clientX - startX));
        const ny = Math.max(0, startTop + (ev.clientY - startY));
        pos.x = nx; pos.y = ny;
        box.style.left = nx + "px";
        box.style.top = ny + "px";
        redrawLines();
      }
      function onUp(){
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        box.classList.remove("dragging");
        if(moved){
          termPositions[step.id + "::" + branch.key] = { x: pos.x, y: pos.y };
          fieldChanged();
        }
      }
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });
    return box;
  }

  function makeBox(step){
    const box = document.createElement("div");
    box.className = "diagram-box diagram-box-" + (step.type === "periodo" ? "periodo" : "pergunta");
    box.setAttribute("data-step-id", step.id);
    const pos = positions[step.id] || { x:40, y:40 };
    box.style.left = pos.x + "px";
    box.style.top = pos.y + "px";
    const text = htmlToText(step.text);
    let preview;
    if(step.type === "periodo"){
      preview = (text ? text + " — " : "") + "📅 Abre o calendário no chat para o cliente escolher a data inicial e final.";
    } else {
      preview = text ? (text.length > 60 ? text.slice(0,60)+"…" : text) : "(sem texto)";
    }
    box.innerHTML = `
      <div class="db-head">
        <span>${diagramBranchIcon(step)} Etapa ${stepNumber(err, step.id)}</span>
        <div class="db-actions">
          <button class="db-edit" title="Editar na aba 3">✎</button>
          <button class="db-del" title="Excluir etapa">×</button>
        </div>
      </div>
      <div class="db-body">${escapeHtml(preview)}</div>
      <div class="db-branches"></div>
    `;
    box.querySelector(".db-edit").onclick = () => {
      activeTab = "agente";
      renderMain();
      setTimeout(() => highlightStep(step.id), 50);
    };
    box.querySelector(".db-del").onclick = () => {
      removeStepAndReferences(err, step.id);
      fieldChanged();
      renderTabDiagrama(err);
    };
    const branchesWrap = box.querySelector(".db-branches");
    stepBranchTargets(step).forEach(branch => {
      branch.ownerStepId = step.id;
      const row = document.createElement("div");
      row.className = "diagram-branch-row";
      row.setAttribute("data-step-id", step.id);
      row.setAttribute("data-branch-key", branch.key);
      const summary = diagramAfterSummary(branch.after);
      const labelText = branch.label ? branch.label : (step.type === "periodo" ? "após período" : "após resposta");
      row.innerHTML = `<span class="db-label">${escapeHtml(labelText)}${summary ? " — " + summary : ""}</span>`;
      const isEmpty = !branch.after || !branch.after.kind;
      const port = document.createElement("div");
      port.className = isEmpty ? "diagram-port diagram-port-empty" : "diagram-port";
      if(isEmpty) port.textContent = "+ ligar";
      port.setAttribute("data-step-id", step.id);
      port.setAttribute("data-branch-key", branch.key);
      row.appendChild(port);
      branchesWrap.appendChild(row);

      port.addEventListener("mousedown", e => {
        e.preventDefault(); e.stopPropagation();
        closePopover();
        const startX = e.clientX, startY = e.clientY;
        let moved = false;
        const tempPath = document.createElementNS("http://www.w3.org/2000/svg", "path");
        tempPath.setAttribute("stroke", "var(--primary)");
        tempPath.setAttribute("stroke-width", "2");
        tempPath.setAttribute("fill", "none");
        svg.appendChild(tempPath);
        const tempPathOver = document.createElementNS("http://www.w3.org/2000/svg", "path");
        tempPathOver.setAttribute("stroke", "var(--primary)");
        tempPathOver.setAttribute("stroke-width", "2");
        tempPathOver.setAttribute("stroke-opacity", "0.22");
        tempPathOver.setAttribute("stroke-width", "1.5");
        tempPathOver.setAttribute("stroke-dasharray", "9 7");
        tempPathOver.setAttribute("fill", "none");
        svg.appendChild(tempPathOver);
        const sourceBox = boxEl(step.id);
        const previewDot = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        previewDot.setAttribute("r", "7");
        previewDot.setAttribute("fill", "#ef4444");
        previewDot.setAttribute("stroke", "#fff");
        previewDot.setAttribute("stroke-width", "2");
        previewDot.style.display = "none";
        svg.appendChild(previewDot);
        function onMove(ev){
          if(Math.abs(ev.clientX - startX) > 4 || Math.abs(ev.clientY - startY) > 4) moved = true;
          const pr = canvas.getBoundingClientRect();
          const p1 = centerOf(port, canvas);
          const p2 = { x: ev.clientX - pr.left, y: ev.clientY - pr.top };
          const obstacles = [...canvas.querySelectorAll(".diagram-box, .diagram-term")]
            .filter(el => el !== sourceBox)
            .map(rectOf);
          const segs = splitLineByObstacles(p1, p2, obstacles);
          tempPath.setAttribute("d", segs.clear.map(s => `M ${s[0].x} ${s[0].y} L ${s[1].x} ${s[1].y}`).join(" "));
          tempPathOver.setAttribute("d", segs.over.map(s => `M ${s[0].x} ${s[0].y} L ${s[1].x} ${s[1].y}`).join(" "));
          const candidate = candidateBoxAt(ev.clientX, ev.clientY);
          if(candidate && candidate.getAttribute("data-step-id") === step.id){
            setDropHighlight(null, true);
            previewDot.style.display = "none";
          } else if(candidate && candidate.classList.contains("diagram-term")){
            setDropHighlight(candidate, false);
            previewDot.style.display = "none";
          } else if(candidate){
            setDropHighlight(candidate, true);
            const cr0 = candidate.getBoundingClientRect();
            const cr = { left: cr0.left - pr.left, right: cr0.right - pr.left, top: cr0.top - pr.top, bottom: cr0.bottom - pr.top, width: cr0.width, height: cr0.height };
            const { edge, ratio } = pickEdgeAndRatio(p1, cr, p2.x, p2.y);
            const dot = pointForEdge(edge, ratio, cr);
            previewDot.setAttribute("cx", dot.x);
            previewDot.setAttribute("cy", dot.y);
            previewDot.style.display = "";
          } else {
            setDropHighlight(null, true);
            previewDot.style.display = "none";
          }
        }
        function onUp(ev){
          document.removeEventListener("mousemove", onMove);
          previewDot.remove();
          document.removeEventListener("mouseup", onUp);
          tempPath.remove();
          tempPathOver.remove();
          clearDropHighlight();
          if(moved){
            const targetBox = candidateBoxAt(ev.clientX, ev.clientY);
            if(targetBox && targetBox.classList.contains("diagram-term")){
              return;
            }
            if(targetBox && targetBox.getAttribute("data-step-id") !== step.id){
              const pr2 = canvas.getBoundingClientRect();
              const p1 = centerOf(port, canvas);
              const tr0 = targetBox.getBoundingClientRect();
              const tr = { left: tr0.left - pr2.left, right: tr0.right - pr2.left, top: tr0.top - pr2.top, bottom: tr0.bottom - pr2.top, width: tr0.width, height: tr0.height };
              const { edge, ratio: anchor } = pickEdgeAndRatio(p1, tr, ev.clientX - pr2.left, ev.clientY - pr2.top);
              setBranchAfter(branch, { kind:"step", step_id: targetBox.getAttribute("data-step-id"), target_anchor: anchor });
              renderTabDiagrama(err);
            }
          } else if(!branch.after || !branch.after.kind){
            openPortPopover(branch, port);
          } else if(armedPort && armedPort.portEl === port){
            disarmPort();
            openPortPopover(branch, port);
          } else {
            armPort(branch, port);
          }
        }
        document.addEventListener("mousemove", onMove);
        document.addEventListener("mouseup", onUp);
      });
    });

    box.addEventListener("mousedown", e => {
      if(e.target.closest(".diagram-port") || e.target.closest("button")) return;
      if(armedPort) return;
      closePopover();
      box.classList.add("dragging");
      const startX = e.clientX, startY = e.clientY;
      const startLeft = pos.x, startTop = pos.y;
      function onMove(ev){
        const nx = Math.max(0, startLeft + (ev.clientX - startX));
        const ny = Math.max(0, startTop + (ev.clientY - startY));
        pos.x = nx; pos.y = ny;
        box.style.left = nx + "px";
        box.style.top = ny + "px";
        redrawLines();
      }
      function onUp(){
        document.removeEventListener("mousemove", onMove);
        document.removeEventListener("mouseup", onUp);
        box.classList.remove("dragging");
        positions[step.id] = { x: pos.x, y: pos.y };
        fieldChanged();
      }
      document.addEventListener("mousemove", onMove);
      document.addEventListener("mouseup", onUp);
    });

    return box;
  }

  ef.flow_steps.forEach(step => canvas.appendChild(makeBox(step)));
  ef.flow_steps.forEach(step => {
    stepBranchTargets(step).forEach(branch => {
      branch.ownerStepId = step.id;
      if(branch.after && (branch.after.kind === "message" || branch.after.kind === "apply_correction")){
        canvas.appendChild(makeTermBox(step, branch));
      }
    });
  });
  redrawLines();

  document.getElementById("btnDiagAddQuestion").onclick = () => {
    const step = newFlowStep("question");
    ef.flow_steps.push(step);
    if(!ef.start_step_id) ef.start_step_id = step.id;
    positions[step.id] = { x: 40, y: maxY + 40 };
    fieldChanged();
    renderTabDiagrama(err);
  };
  document.getElementById("btnDiagAddPeriodo").onclick = () => {
    const step = newFlowStep("periodo");
    ef.flow_steps.push(step);
    if(!ef.start_step_id) ef.start_step_id = step.id;
    positions[step.id] = { x: 40, y: maxY + 40 };
    fieldChanged();
    renderTabDiagrama(err);
  };
  document.getElementById("btnDiagAutoLayout").onclick = () => {
    renderPathExpansionView(err);
  };
}

/* ---- PATH EXPANSION VIEW ---- */
function findAllPaths(ef){
  const paths = [];
  function dfs(stepId, currentPath, visited){
    if(visited.has(stepId)){
      paths.push([...currentPath, { type:"step", stepId, isCycle:true }]);
      return;
    }
    const step = ef.flow_steps.find(s => s.id === stepId);
    if(!step){ if(currentPath.length) paths.push([...currentPath]); return; }
    const node = { type:"step", stepId };
    const branches = stepBranchTargets(step).filter(b => b.after && b.after.kind);
    if(!branches.length){
      paths.push([...currentPath, node]);
      return;
    }
    const newVisited = new Set(visited); newVisited.add(stepId);
    branches.forEach(branch => {
      if(branch.after.kind === "step" && branch.after.step_id){
        dfs(branch.after.step_id, [...currentPath, node], newVisited);
      } else {
        paths.push([...currentPath, node, { type:"term", stepId, branchKey:branch.key, branch }]);
      }
    });
  }
  if(ef.start_step_id) dfs(ef.start_step_id, [], new Set());
  if(!paths.length && ef.flow_steps.length){
    ef.flow_steps.forEach(s => paths.push([{ type:"step", stepId:s.id }]));
  }
  return paths;
}

function renderPathExpansionView(err){
  const p = document.getElementById("panelDiagrama");
  if(!p) return;
  if(window.__diagramDisarmPort) window.__diagramDisarmPort();
  const ef = err.agent_flow;
  const paths = findAllPaths(ef);

  const COL_W  = 260;
  const ROW_H  = 170;
  const BOX_W  = 220;
  const BOX_H  = 100;
  const START_X = 30;
  const START_Y = 20;

  const maxDepth = paths.reduce((m, path) => Math.max(m, path.length), 0);
  const canvasW = START_X + paths.length * COL_W + 40;
  const canvasH = START_Y + maxDepth * ROW_H + BOX_H + 40;

  p.innerHTML = `
    <div class="hint" style="margin-bottom:10px;">Visão de caminhos — cada coluna é um caminho independente do fluxo. Nós compartilhados aparecem em cada coluna. Use <strong>← Voltar ao editor</strong> para editar conexões.</div>
    <div class="diagram-legend">
      <span class="lg-item"><span class="lg-dot" style="background:#7a1f6e;"></span> Pergunta</span>
      <span class="lg-item"><span class="lg-dot" style="background:#2560b8;"></span> Período</span>
      <span class="lg-item"><span class="lg-dot" style="background:#9a6512;"></span> Mensagem final</span>
      <span class="lg-item"><span class="lg-dot" style="background:#0f7a66;"></span> Corrigir vendas</span>
    </div>
    <button class="btn-ghost btn-sm" id="btnPathBack" style="border-color:var(--teal);color:var(--teal);">← Voltar ao editor</button>
    <div id="pathExpCanvas" style="position:relative;overflow:auto;border:1px solid var(--border);border-radius:8px;margin-top:10px;height:600px;background-color:var(--bg-soft);background-image:radial-gradient(circle,#d8dee2 1px,transparent 1px);background-size:18px 18px;">
      <div id="pathExpInner" style="position:relative;width:${canvasW}px;height:${canvasH}px;">
        <svg id="pathExpSvg" style="position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;overflow:visible;z-index:1;">
          <defs>
            <marker id="peArrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
              <path d="M0,0 L6,3 L0,6 Z" fill="#888"></path>
            </marker>
          </defs>
        </svg>
      </div>
    </div>
  `;

  const inner = document.getElementById("pathExpInner");
  const svg   = document.getElementById("pathExpSvg");

  function stepLabel(stepId){
    const step = ef.flow_steps.find(s => s.id === stepId);
    if(!step) return "(?)";
    const n = ef.flow_steps.findIndex(s => s.id === stepId) + 1;
    const text = htmlToText(step.text) || "";
    const preview = text.length > 55 ? text.slice(0,55)+"…" : text;
    const icon = diagramBranchIcon(step);
    return `<strong>${icon} Etapa ${n}</strong><br><span style="font-size:11px;color:var(--text-muted,#666);">${escapeHtml(preview)||"(sem texto)"}</span>`;
  }

  paths.forEach((path, colIdx) => {
    const colX = START_X + colIdx * COL_W;
    let prevBoxBottom = null;
    let prevBoxCenterX = null;

    path.forEach((node, rowIdx) => {
      const boxX = colX;
      const boxY = START_Y + rowIdx * ROW_H;
      const centerX = boxX + BOX_W / 2;
      const boxBottom = boxY + BOX_H;

      // Draw arrow from previous box
      if(prevBoxBottom !== null){
        const line = document.createElementNS("http://www.w3.org/2000/svg","line");
        line.setAttribute("x1", prevBoxCenterX);
        line.setAttribute("y1", prevBoxBottom);
        line.setAttribute("x2", centerX);
        line.setAttribute("y2", boxY);
        line.setAttribute("stroke", "#aaa");
        line.setAttribute("stroke-width", "2");
        line.setAttribute("marker-end", "url(#peArrow)");
        svg.appendChild(line);
      }

      const box = document.createElement("div");
      if(node.type === "term"){
        const isCorr = node.branch && node.branch.after && node.branch.after.kind === "apply_correction";
        box.className = "diagram-box diagram-term diagram-term-" + (isCorr ? "correction" : "message");
        box.style.borderStyle = "dashed";
        const icon = isCorr ? "✅" : "💬";
        const text = node.branch && node.branch.after ? htmlToText(node.branch.after.text) || "(sem texto)" : "(sem texto)";
        box.innerHTML = `<div class="db-head"><span>${icon} Fim</span></div><div class="db-body" style="font-size:11px;">${escapeHtml(text)}</div>`;
      } else {
        const step = ef.flow_steps.find(s => s.id === node.stepId);
        const isPeriodo = step && step.type === "periodo";
        box.className = "diagram-box diagram-box-" + (isPeriodo ? "periodo" : "pergunta");
        box.style.cursor = "default";
        box.innerHTML = `
          <div class="db-head">
            <span>${stepLabel(node.stepId)}</span>
            <div class="db-actions">
              <button class="db-edit path-edit-btn" data-step-id="${node.stepId}" title="Editar na aba 3" style="cursor:pointer;">✎</button>
            </div>
          </div>
        `;
        if(node.isCycle){
          const badge = document.createElement("div");
          badge.style = "font-size:10px;color:#888;padding:0 8px 4px;";
          badge.textContent = "↺ ciclo";
          box.appendChild(badge);
        }
      }

      box.style.left = boxX + "px";
      box.style.top  = boxY + "px";
      box.style.width = BOX_W + "px";
      box.style.minHeight = BOX_H + "px";
      box.style.zIndex = "2";
      inner.appendChild(box);

      prevBoxBottom  = boxBottom;
      prevBoxCenterX = centerX;
    });
  });

  // Wire edit buttons
  inner.querySelectorAll(".path-edit-btn").forEach(btn => {
    btn.addEventListener("click", e => {
      e.stopPropagation();
      const stepId = btn.getAttribute("data-step-id");
      activeTab = "agente";
      renderMain();
      setTimeout(() => highlightStep(stepId), 50);
    });
  });

  document.getElementById("btnPathBack").onclick = () => renderTabDiagrama(err);
}

function todayBR(){
  const d = new Date();
  return String(d.getDate()).padStart(2,'0') + "/" + String(d.getMonth()+1).padStart(2,'0') + "/" + d.getFullYear();
}
function substituteVars(text){
  return (text||"").split("{{data_atual}}").join(todayBR());
}

function describeFlowFromStep(ef, stepId, indent, visited){
  if(!stepId) return "";
  if(visited.has(stepId)) return `${indent}(retorna à etapa ${stepId} — possível ciclo)\n`;
  const step = ef.flow_steps.find(s => s.id === stepId);
  if(!step) return `${indent}(etapa "${stepId}" não encontrada)\n`;
  visited = new Set(visited); visited.add(stepId);
  let out = "";
  const n = ef.flow_steps.findIndex(s => s.id === step.id) + 1;
  if(step.type === "periodo"){
    const calDesc = step.calendar_mode === "data_unica" ? "solicitar data única" : "solicitar data inicial e final";
    out += `${indent}ETAPA ${n} Coleta de ${step.calendar_mode === "data_unica" ? "data única" : "período"}: ${htmlToText(step.text) || calDesc}\n`;
    out += describeAfter(ef, step.after, indent + "  ", visited);
  } else {
    out += `${indent}ETAPA ${n} Pergunta (${step.response_type}): ${htmlToText(step.text)}\n`;
    if(step.response_type === "texto_livre"){
      out += describeAfter(ef, step.after, indent + "  ", visited);
    } else {
      (step.options||[]).forEach(opt => {
        out += `${indent}  SE responder "${opt.label}":\n`;
        out += describeAfter(ef, opt.after, indent + "    ", visited);
      });
    }
  }
  return out;
}

function describeAfter(ef, after, indent, visited){
  if(!after || !after.kind) return `${indent}(sem destino definido)\n`;
  if(after.kind === "step") return describeFlowFromStep(ef, after.step_id, indent, visited);
  if(after.kind === "message") return `${indent}Exibir mensagem final: "${substituteVars(after.text)}"\n`;
  if(after.kind === "apply_correction") return `${indent}Aplicar correção nas vendas afetadas e exibir mensagem final: "${substituteVars(after.text)}"\n`;
  return "";
}

function buildFlowScriptHtml(ef, stepId, depth, visited){
  if(!stepId) return "";
  if(visited.has(stepId)) return `<div class="hint" style="margin-left:${depth*20}px;">(retorna a uma etapa anterior — possível ciclo)</div>`;
  const step = ef.flow_steps.find(s => s.id === stepId);
  if(!step) return `<div class="hint" style="margin-left:${depth*20}px;">(etapa não encontrada)</div>`;
  visited = new Set(visited); visited.add(stepId);
  const n = ef.flow_steps.findIndex(s => s.id === step.id) + 1;
  const qtext = escapeHtml(htmlToText(step.text)) || "(sem texto)";
  let html = `<div class="flow-script-step" style="margin-left:${depth*20}px;">`;
  html += `<div class="flow-script-q"><strong>${n})</strong> ${qtext}</div>`;
  if(step.type === "periodo"){
    const calHint = step.calendar_mode === "data_unica" ? "📅 Mostrar o calendário. Cliente escolhe uma data." : "📅 Mostrar o calendário. Cliente escolhe a data inicial e final.";
    html += `<div class="hint" style="margin:2px 0 8px;">${calHint}</div>`;
    html += afterScriptHtml(ef, step.after, depth, visited);
  } else if(step.response_type === "texto_livre"){
    html += `<div class="hint" style="margin:2px 0 8px;">✏️ Resposta em texto livre.</div>`;
    html += afterScriptHtml(ef, step.after, depth, visited);
  } else {
    html += `<div class="hint" style="margin:2px 0 4px;">${step.response_type === "sim_nao" ? "Sim/Não:" : "Múltipla escolha:"}</div>`;
    html += `<div style="margin-bottom:8px;">${(step.options||[]).map(o => `( ) ${escapeHtml(o.label)}`).join('<br>') || '<span class="hint">(nenhuma opção cadastrada)</span>'}</div>`;
    (step.options||[]).forEach(opt => {
      html += `<div class="flow-script-branch">`;
      html += `<div class="flow-script-branch-label">Se escolhido: "${escapeHtml(opt.label)}"</div>`;
      html += afterScriptHtml(ef, opt.after, depth + 1, visited);
      html += `</div>`;
    });
  }
  html += `</div>`;
  return html;
}

function afterScriptHtml(ef, after, depth, visited){
  if(!after || !after.kind) return `<div class="hint" style="margin-left:${depth*20}px;">(sem destino definido)</div>`;
  if(after.kind === "step") return buildFlowScriptHtml(ef, after.step_id, depth, visited);
  if(after.kind === "message") return `<div style="margin:4px 0;margin-left:${depth*20}px;">💬 Mensagem final: "${escapeHtml(substituteVars(after.text))}"</div>`;
  if(after.kind === "apply_correction") return `<div style="margin:4px 0;margin-left:${depth*20}px;">✅ Aplica correção nas vendas e exibe mensagem final: "${escapeHtml(substituteVars(after.text))}"</div>`;
  return "";
}

function buildFlowPreviewHtml(ef, stepId, visited){
  if(!stepId) return "";
  if(visited.has(stepId)) return `<li>(retorna a uma etapa anterior — possível ciclo)</li>`;
  const step = ef.flow_steps.find(s => s.id === stepId);
  if(!step) return `<li>(etapa não encontrada)</li>`;
  visited = new Set(visited); visited.add(stepId);
  const n = ef.flow_steps.findIndex(s => s.id === step.id) + 1;
  let html = "";
  if(step.type === "periodo"){
    const calLabel = step.calendar_mode === "data_unica" ? "coleta de data única (calendário)" : "coleta de período (calendário)";
    html += `<li><strong>Etapa ${n}</strong> — ${calLabel}${htmlToText(step.text) ? ': '+escapeHtml(htmlToText(step.text)) : ''}<ul>${afterPreviewHtml(ef, step.after, visited)}</ul></li>`;
  } else {
    const qtext = escapeHtml(htmlToText(step.text)) || "(sem texto)";
    html += `<li><strong>Etapa ${n}</strong> — ${qtext}`;
    if(step.response_type === "texto_livre"){
      html += `<ul>${afterPreviewHtml(ef, step.after, visited)}</ul>`;
    } else {
      html += `<ul>${(step.options||[]).map(opt =>
        `<li>SE responder "${escapeHtml(opt.label)}":<ul>${afterPreviewHtml(ef, opt.after, visited)}</ul></li>`
      ).join('') || '<li>(nenhuma opção cadastrada)</li>'}</ul>`;
    }
    html += `</li>`;
  }
  return html;
}

function afterPreviewHtml(ef, after, visited){
  if(!after || !after.kind) return `<li class="hint">(sem destino definido)</li>`;
  if(after.kind === "step") return buildFlowPreviewHtml(ef, after.step_id, visited);
  if(after.kind === "message") return `<li>Mensagem final: "${escapeHtml(substituteVars(after.text))}"</li>`;
  if(after.kind === "apply_correction") return `<li>Aplica correção nas vendas e exibe mensagem final: "${escapeHtml(substituteVars(after.text))}"</li>`;
  return "";
}

function renderFlowPreview(err){
  const box = document.getElementById("flowPreviewBox");
  if(!box) return;
  const ef = err.agent_flow;
  if(!ef.flow_steps.length){
    box.innerHTML = `<span class="hint">Adicione etapas abaixo para ver o desenho do fluxo aqui.</span>`;
    return;
  }
  box.innerHTML = buildFlowScriptHtml(ef, ef.start_step_id, 0, new Set()) || '<span class="hint">Defina a etapa inicial do fluxo acima.</span>';
}

function updateSystemPrompt(err){
  renderFlowPreview(err);
  const box = document.getElementById("systemPromptBox");
  if(!box) return;
  const ef = err.agent_flow;
  let prompt = `Você é o agente automático de suporte da eNotas para o erro ${err.code} (${GROUP_LABELS[err.group]||err.group}).\n\n`;
  prompt += `MENSAGEM ORIGINAL DO SISTEMA:\n"${err.original_message}"\n\n`;
  if(err.client_facing.title) prompt += `TÍTULO PARA O CLIENTE: ${err.client_facing.title}\n`;
  const descText = htmlToText(err.client_facing.description);
  if(descText) prompt += `DESCRIÇÃO AMIGÁVEL: ${descText}\n`;
  const stepsText = err.client_facing.steps.map(htmlToText).filter(Boolean);
  if(stepsText.length){
    prompt += `\nPASSO A PASSO DE SOLUÇÃO:\n`;
    stepsText.forEach((s,i) => prompt += `${i+1}. ${s}\n`);
  }
  if(ef.flow_steps.length){
    prompt += `\nFLUXO DE PERGUNTAS E AÇÕES (siga a árvore abaixo de acordo com as respostas do cliente):\n`;
    prompt += describeFlowFromStep(ef, ef.start_step_id, "", new Set());
  }
  prompt += `\nESCALONAMENTO: se não conseguir resolver, pergunte ao cliente: "As correções não foram possíveis ser aplicadas, deseja seguir com a abertura de um chamado para o nosso suporte técnico?"`;
  err.agent_flow.system_prompt_preview = prompt;
  box.textContent = prompt;
}

/* ================= SIMULAÇÃO DO BOT ================= */
const SIM_NAMES = ["João Silva","Maria Souza","Carlos Pereira","Ana Oliveira","Pedro Santos","Fernanda Lima","Bruno Costa","Juliana Rocha"];
const SIM_PRODUCTS = ["Plano Mensal","Plano Anual","Emissão Avulsa","Plano Empresarial","Add-on NFS-e"];

function openBotSimulation(err){
  const overlay = document.createElement("div");
  overlay.className = "bot-sim-overlay";
  overlay.innerHTML = `
    <div class="bot-sim-modal">
      <div class="bot-sim-header">
        <strong>Simular bot — ${escapeHtml(err.code)}</strong>
        <button id="botSimClose">×</button>
      </div>
      <div class="bot-sim-chat" id="botSimChat"></div>
    </div>
  `;
  document.body.appendChild(overlay);
  overlay.querySelector("#botSimClose").onclick = () => overlay.remove();
  overlay.onclick = e => { if(e.target === overlay) overlay.remove(); };

  const chat = overlay.querySelector("#botSimChat");
  const answers = [];

  function scrollDown(){ chat.scrollTop = chat.scrollHeight; }
  function addBotMsg(html){
    const div = document.createElement("div");
    div.className = "bot-sim-msg bot";
    div.innerHTML = html;
    chat.appendChild(div);
    scrollDown();
  }
  function addUserMsg(text){
    const div = document.createElement("div");
    div.className = "bot-sim-msg user";
    div.textContent = text;
    chat.appendChild(div);
    scrollDown();
  }
  function clearInteractive(){
    const old = chat.querySelector(".bot-sim-interactive");
    if(old) old.remove();
  }
  function addInteractive(buildFn){
    clearInteractive();
    const div = document.createElement("div");
    div.className = "bot-sim-interactive";
    buildFn(div);
    chat.appendChild(div);
    scrollDown();
  }

  const title = err.client_facing.title || err.code;
  addBotMsg(`Identifiquei o erro <strong>${escapeHtml(title)}</strong>. Vou te fazer algumas perguntas antes de seguir.`);

  function walkStep(stepId){
    const ef = err.agent_flow;
    if(!stepId){
      addBotMsg(`Não encontrei uma ação configurada para essas respostas. ${htmlToText(ef.escalation.message) || "Vou escalar para o suporte humano."}`);
      return;
    }
    const step = ef.flow_steps.find(s => s.id === stepId);
    if(!step){
      addBotMsg(`Não encontrei uma ação configurada para essas respostas. ${htmlToText(ef.escalation.message) || "Vou escalar para o suporte humano."}`);
      return;
    }
    if(step.type === "periodo"){
      if(htmlToText(step.text)) addBotMsg(htmlToText(step.text));
      if(step.calendar_mode === "data_unica"){
        addBotMsg("Informe a data:");
        addInteractive(div => {
          const dateInput = document.createElement("input"); dateInput.type = "date";
          const btn = document.createElement("button");
          btn.textContent = "Enviar";
          btn.onclick = () => {
            if(!dateInput.value) return;
            addUserMsg(dateInput.value); clearInteractive();
            handleAfter(step.after, { date: dateInput.value });
          };
          div.appendChild(dateInput); div.appendChild(btn);
        });
      } else {
        addBotMsg("Informe o período (data inicial e final):");
        addInteractive(div => {
          const start = document.createElement("input"); start.type = "date";
          const end = document.createElement("input"); end.type = "date";
          const btn = document.createElement("button");
          btn.textContent = "Enviar";
          btn.onclick = () => {
            if(!start.value || !end.value) return;
            addUserMsg(`${start.value} até ${end.value}`); clearInteractive();
            handleAfter(step.after, { start:start.value, end:end.value });
          };
          div.appendChild(start); div.appendChild(end); div.appendChild(btn);
        });
      }
      return;
    }
    addBotMsg(htmlToText(step.text) || "Pergunta");
    if(step.response_type === "sim_nao" || step.response_type === "multipla_escolha"){
      addInteractive(div => {
        (step.options||[]).forEach(opt => {
          const btn = document.createElement("button");
          btn.textContent = opt.label;
          btn.onclick = () => { addUserMsg(opt.label); clearInteractive(); handleAfter(opt.after, {}); };
          div.appendChild(btn);
        });
      });
    } else {
      addInteractive(div => {
        const input = document.createElement("input");
        input.type = "text";
        input.placeholder = "Digite sua resposta...";
        const btn = document.createElement("button");
        btn.textContent = "Enviar";
        btn.onclick = () => {
          const val = input.value.trim();
          if(!val) return;
          addUserMsg(val); clearInteractive(); handleAfter(step.after, { text:val });
        };
        input.onkeydown = e => { if(e.key === "Enter") btn.click(); };
        div.appendChild(input); div.appendChild(btn);
      });
    }
  }

  function substituteVarsSim(text){
    return (text||"").split("{{data_atual}}").join(todayBR());
  }

  function handleAfter(after, params){
    if(!after || !after.kind){
      addBotMsg(`Não encontrei um destino configurado para essa resposta. ${htmlToText(err.agent_flow.escalation.message) || "Vou escalar para o suporte humano."}`);
      return;
    }
    if(after.kind === "step"){ walkStep(after.step_id); return; }
    if(after.kind === "message"){ addBotMsg(substituteVarsSim(after.text)); return; }
    if(after.kind === "apply_correction"){ askScope(substituteVarsSim(after.text), params); return; }
  }

  let pendingFinalMessage = "";

  function askScope(finalMessage, periodoParams){
    pendingFinalMessage = finalMessage || "";
    if(periodoParams && periodoParams.start && periodoParams.end){
      showAffectedSales("periodo", periodoParams);
      return;
    }
    addBotMsg("Em quais vendas devo aplicar essa correção?");
    addInteractive(div => {
      [
        ["especifica","Uma venda específica"],
        ["periodo","Um período entre datas"],
        ["produto","Um produto específico"],
        ["todas","Todas as vendas com esse erro"]
      ].forEach(([key,label]) => {
        const btn = document.createElement("button");
        btn.textContent = label;
        btn.onclick = () => { addUserMsg(label); clearInteractive(); handleScopeChoice(key); };
        div.appendChild(btn);
      });
    });
  }

  function handleScopeChoice(scope){
    if(scope === "especifica"){
      addBotMsg("Informe o código/número da venda:");
      addInteractive(div => {
        const input = document.createElement("input");
        input.type = "text";
        input.placeholder = "Ex.: VND-1023";
        const btn = document.createElement("button");
        btn.textContent = "Enviar";
        btn.onclick = () => {
          const val = input.value.trim();
          if(!val) return;
          addUserMsg(val); clearInteractive();
          showAffectedSales(scope, { saleId: val });
        };
        input.onkeydown = e => { if(e.key === "Enter") btn.click(); };
        div.appendChild(input); div.appendChild(btn);
      });
    } else if(scope === "periodo"){
      addBotMsg("Informe o período (data inicial e final):");
      addInteractive(div => {
        const start = document.createElement("input"); start.type = "date";
        const end = document.createElement("input"); end.type = "date";
        const btn = document.createElement("button");
        btn.textContent = "Enviar";
        btn.onclick = () => {
          if(!start.value || !end.value) return;
          addUserMsg(`${start.value} até ${end.value}`); clearInteractive();
          showAffectedSales(scope, { start: start.value, end: end.value });
        };
        div.appendChild(start); div.appendChild(end); div.appendChild(btn);
      });
    } else if(scope === "produto"){
      addBotMsg("Informe o nome do produto:");
      addInteractive(div => {
        const input = document.createElement("input");
        input.type = "text";
        input.placeholder = "Ex.: Plano Mensal";
        const btn = document.createElement("button");
        btn.textContent = "Enviar";
        btn.onclick = () => {
          const val = input.value.trim();
          if(!val) return;
          addUserMsg(val); clearInteractive();
          showAffectedSales(scope, { product: val });
        };
        input.onkeydown = e => { if(e.key === "Enter") btn.click(); };
        div.appendChild(input); div.appendChild(btn);
      });
    } else {
      showAffectedSales(scope, {});
    }
  }

  function mockSales(scope, params){
    const count = scope === "especifica" ? 1 : (scope === "todas" ? 5 : 3);
    const sales = [];
    for(let i = 0; i < count; i++){
      sales.push({
        id: scope === "especifica" ? params.saleId : `VND-${1000 + Math.floor(Math.random()*9000)}`,
        cliente: SIM_NAMES[(i + err.code.length) % SIM_NAMES.length],
        produto: params.product || SIM_PRODUCTS[(i + 1) % SIM_PRODUCTS.length],
        data: params.start ? params.start : `2026-0${(i%6)+1}-1${i}`,
        valor: `R$ ${(99 + i*37).toFixed(2)}`
      });
    }
    return sales;
  }

  function showAffectedSales(scope, params){
    const sales = mockSales(scope, params);
    const rows = sales.map(s => `<tr><td>${escapeHtml(s.id)}</td><td>${escapeHtml(s.cliente)}</td><td>${escapeHtml(s.produto)}</td><td>${escapeHtml(s.data)}</td><td>${escapeHtml(s.valor)}</td></tr>`).join("");
    addBotMsg(`
      Encontrei ${sales.length} venda(s) que seriam afetadas (simulação):
      <table class="bot-sim-table">
        <thead><tr><th>Venda</th><th>Cliente</th><th>Produto</th><th>Data</th><th>Valor</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      Posso aplicar a tratativa nessas vendas?
    `);
    addInteractive(div => {
      const ok = document.createElement("button");
      ok.textContent = "Sim, aplicar";
      ok.onclick = () => { addUserMsg("Sim, aplicar"); clearInteractive(); finalizeApplication(sales); };
      const back = document.createElement("button");
      back.textContent = "Voltar";
      back.onclick = () => { addUserMsg("Voltar"); clearInteractive(); askScope(); };
      div.appendChild(ok); div.appendChild(back);
    });
  }

  function finalizeApplication(sales){
    addBotMsg(`Tratativa aplicada com sucesso em ${sales.length} venda(s).`);
    if(pendingFinalMessage) addBotMsg(pendingFinalMessage);
  }

  walkStep(err.agent_flow.start_step_id);
}

/* ================= NOVO ERRO ================= */
document.getElementById("btnNew").onclick = () => {
  const code = prompt("Código do novo erro:");
  if(!code) return;
  if(state.errors.some(e => e.code === code)){ alert("Já existe um erro com esse código."); return; }
  const newErr = {
    code, group:"portal_nacional", original_message:"", match_patterns:[code],
    requires_prefecture:false, status:"nao_mapeado",
    client_facing:{ title:"", title_suggestions:[], description:"", steps:[], extra_tip:"" },
    agent_flow:{ flow_steps:[], start_step_id:null, post_fix_followup:{ enabled:false, message:"" }, escalation:{ after_attempts:3, message:"", zendesk_url:"" }, system_prompt_preview:"" }
  };
  state.errors.push(newErr);
  selectedCode = code;
  fieldChanged();
  render();
};

document.getElementById("btnSaveNow").onclick = () => saveToGist(false);

// btnHelp is wired by setupHelpModal()

document.getElementById("btnExport").onclick = () => {
  const exportData = { version:"1.0", exported_at:new Date().toISOString(), errors: state.errors };
  const blob = new Blob([JSON.stringify(exportData, null, 2)], { type:"application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "errors.json";
  a.click();
  URL.revokeObjectURL(url);
};

/* ================= LOGO ================= */
(function setupLogo(){
  const slot = document.getElementById("logoSlot");
  const img = new Image();
  img.onload = () => { slot.innerHTML = ""; slot.appendChild(img); };
  img.onerror = () => {};
  img.src = "logo-enotas.png";
})();

/* ================= HELPERS ================= */
function escapeHtml(str){
  return String(str ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
}
function escapeAttr(str){ return escapeHtml(str); }

function htmlToText(html){
  const div = document.createElement("div");
  div.innerHTML = String(html ?? "");
  return (div.textContent || "").trim();
}

/* ================= EDITOR DE TEXTO RICO =================
   Toolbar baseada no padrão do guia-cr: bloco (Normal/Título), citação,
   negrito, itálico, sublinhado, riscado, listas, link e limpar formatação. */
function richToolbarHTML(){
  return `
    <div class="rt-toolbar">
      <select class="rt-block" title="Estilo do bloco">
        <option value="P">Normal</option>
        <option value="H3">Título</option>
      </select>
      <button type="button" data-cmd="formatBlock" data-val="BLOCKQUOTE" title="Citação">&rdquo;</button>
      <button type="button" data-cmd="bold" title="Negrito"><b>B</b></button>
      <button type="button" data-cmd="italic" title="Itálico"><i>I</i></button>
      <button type="button" data-cmd="underline" title="Sublinhado"><u>U</u></button>
      <button type="button" data-cmd="strikeThrough" title="Riscado"><s>S</s></button>
      <button type="button" data-cmd="insertOrderedList" title="Lista numerada">1.</button>
      <button type="button" data-cmd="insertUnorderedList" title="Lista">•</button>
      <button type="button" data-cmd="createLink" title="Inserir link">🔗</button>
      <button type="button" data-cmd="removeFormat" title="Limpar formatação">Tx</button>
    </div>
  `;
}

function mountRichEditor(container, html, placeholder, onChange){
  container.innerHTML = richToolbarHTML() + `<div class="rt-content" contenteditable="true" data-placeholder="${escapeAttr(placeholder||'')}"></div>`;
  const content = container.querySelector(".rt-content");
  content.innerHTML = html || "";
  content.setAttribute("data-empty", content.innerHTML.trim() ? "false" : "true");
  container.querySelectorAll(".rt-toolbar button").forEach(btn => {
    btn.onclick = () => {
      content.focus();
      const cmd = btn.dataset.cmd;
      if(cmd === "createLink"){
        const url = window.prompt("URL do link:");
        if(url) document.execCommand(cmd, false, url);
      } else if(cmd === "formatBlock"){
        document.execCommand(cmd, false, btn.dataset.val);
      } else {
        document.execCommand(cmd, false, null);
      }
      content.setAttribute("data-empty", content.innerHTML.trim() ? "false" : "true");
      onChange(content.innerHTML);
    };
  });
  container.querySelector(".rt-block").onchange = e => {
    content.focus();
    document.execCommand("formatBlock", false, e.target.value);
    onChange(content.innerHTML);
  };
  content.oninput = () => {
    content.setAttribute("data-empty", content.innerHTML.trim() ? "false" : "true");
    onChange(content.innerHTML);
  };
  return content;
}

/* ================= INIT ================= */
setupHelpModal();

(function setupAuth(){
  const overlay = document.getElementById("authOverlay");
  const input   = document.getElementById("authInput");
  const btn     = document.getElementById("authBtn");
  const errEl   = document.getElementById("authErr");

  async function tryUnlock(){
    errEl.textContent = "";
    btn.disabled = true;
    btn.textContent = "Verificando...";
    try {
      _token = await decryptToken(input.value);
      overlay.remove();
      applyHash();
      loadFromGist();
    } catch(e) {
      _token = null;
      errEl.textContent = "Senha incorreta. Tente novamente.";
      input.value = "";
      input.focus();
    } finally {
      btn.disabled = false;
      btn.textContent = "Entrar";
    }
  }

  btn.addEventListener("click", tryUnlock);
  input.addEventListener("keydown", e => { if(e.key === "Enter") tryUnlock(); });
})();
