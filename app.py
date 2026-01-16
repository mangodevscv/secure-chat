from flask import Flask, request, jsonify, render_template
import json
import os
from datetime import datetime, timedelta
import crypto_utils as crypto
import hashlib

app = Flask(__name__)

# =====================
# Persistência de dados
# =====================
DATA_DIR = "data"
DIR_FILE = f"{DATA_DIR}/directory.json"
MSG_FILE = f"{DATA_DIR}/messages.json"
INTRUDER_FILE = f"{DATA_DIR}/intruder.json"
CLS_FILE = f"{DATA_DIR}/clients.json"
SESSION_KEYS_FILE = f"{DATA_DIR}/session_keys.json"

os.makedirs(DATA_DIR, exist_ok=True)

def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r") as f:
        return json.load(f)

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

# =====================
# Estado do sistema
# =====================
directory = load_json(DIR_FILE, {})      # AR - Autoridade de Registo
messages = load_json(MSG_FILE, [])
intruder_logs = load_json(INTRUDER_FILE, [])
clients_data = load_json(CLS_FILE, {})   # Dados persistidos dos clientes
session_keys_data = load_json(SESSION_KEYS_FILE, {})  # Chaves de sessão com validade

# Cache em memória para objetos criptográficos (não serializáveis)
clients_cache = {}  # {cid: {"priv": key_obj, "pub": key_obj}}
sessions = {}       # {(cid, peer): session_key}

# =====================
# Funções auxiliares
# =====================
def save_clients():
    """Salva clientes no JSON"""
    save_json(CLS_FILE, clients_data)

def save_session_keys():
    """Salva chaves de sessão no JSON"""
    save_json(SESSION_KEYS_FILE, session_keys_data)

def hash_pin(pin):
    return hashlib.sha256(pin.encode()).hexdigest()

def verify_pin(pin, hashed_pin):
    return hash_pin(pin) == hashed_pin

def get_client_keys(cid):
    """Obtém as chaves de um cliente do cache ou carrega do JSON"""
    if cid not in clients_cache:
        # Se não está no cache, tenta carregar do disco
        if cid in clients_data and "priv_pem" in clients_data[cid]:
            priv_pem = clients_data[cid]["priv_pem"]
            pub_pem = clients_data[cid]["pub_pem"]
            
            clients_cache[cid] = {
                "priv": crypto.load_private(priv_pem),
                "pub": crypto.load_public(pub_pem)
            }
    
    return clients_cache.get(cid)

def save_client_keys(cid, priv, pub):
    """Salva as chaves de um cliente (cache + JSON)"""
    # Cache em memória
    clients_cache[cid] = {
        "priv": priv,
        "pub": pub
    }
    
    # Persistência em JSON (PEM strings)
    clients_data[cid].update({
        "priv_pem": crypto.serialize_private(priv),
        "pub_pem": crypto.serialize_public(pub),
        "has_keys": True,
        "keys_generated_at": datetime.utcnow().isoformat()
    })
    
    save_clients()

def is_session_valid(cid, peer):
    """Verifica se a sessão ainda é válida (baseado no timestamp)"""
    session_id = f"{cid}_{peer}"
    if session_id in session_keys_data:
        session_info = session_keys_data[session_id]
        generated_at = datetime.fromisoformat(session_info["generated_at"])
        
        # Verifica validade (30 minutos por exemplo)
        if datetime.utcnow() - generated_at < timedelta(minutes=30):
            return True
    return False

def get_peer_public_key(cid, peer):
    """Solicita a chave pública de outro cliente registado"""
    if peer not in directory:
        return None
    
    return directory[peer]["public_key"]

# =====================
# Páginas
# =====================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/client/<cid>", methods=["GET", "POST"])
def client(cid):
    if cid not in clients_data:
        return "Cliente não existe", 404
    
    if request.method == "POST":
        # Verificar PIN
        pin = request.form.get("pin", "")
        hashed_pin = clients_data[cid].get("pin_hash", "")
        
        if not verify_pin(pin, hashed_pin):
            return "PIN incorreto", 403
        
        # PIN correto, mostrar página do cliente
        return render_template("client.html", cid=cid, 
                             has_keys=clients_data[cid].get("has_keys", False),
                             published=clients_data[cid].get("published", False))
    
    # GET request - mostrar página de login com PIN
    return render_template("client_login.html", cid=cid)

@app.route("/intruder")
def intruder():
    return render_template("intruder.html")

# =====================
# Clientes dinâmicos
# =====================
@app.route("/client/create", methods=["POST"])
def create_client():
    """Cria um novo cliente no sistema"""
    cid = request.json["id"]
    pin = request.json.get("pin", "")
    
    # Verifica se já existe
    if cid in clients_data:
        return {"error": "Cliente já existe"}, 400
    
    # Valida PIN (mínimo 4 dígitos)
    if len(pin) < 4:
        return {"error": "PIN deve ter pelo menos 4 dígitos"}, 400
    
    # Cria entrada com hash do PIN
    clients_data[cid] = {
        "created_at": datetime.utcnow().isoformat(),
        "has_keys": False,
        "published": False,
        "pin_hash": hash_pin(pin)
    }
    
    save_clients()
    return {"status": f"Cliente {cid} criado"}

@app.route("/client/<cid>/generate", methods=["POST"])
def generate(cid):
    """Gera par de chaves ECC para o cliente"""
    if cid not in clients_data:
        return {"error": "Cliente não existe"}, 400
    
    # Verifica se já tem chaves
    if clients_data[cid].get("has_keys", False):
        return {"error": "Cliente já possui chaves geradas"}, 400
    
    # Gera chaves
    priv, pub = crypto.generate_keys()
    
    # Salva (cache + JSON)
    save_client_keys(cid, priv, pub)
    
    return {
        "status": "keys generated",
        "keys_generated_at": datetime.utcnow().isoformat()
    }

@app.route("/client/<cid>/publish", methods=["POST"])
def publish(cid):
    """Publica a chave pública no diretório (AR)"""
    if cid not in clients_data:
        return {"error": "Cliente não existe"}, 400
    
    keys = get_client_keys(cid)
    if not keys or "pub" not in keys:
        return {"error": "Cliente não possui chaves geradas"}, 400
    
    pub_pem = crypto.serialize_public(keys["pub"])

    directory[cid] = {
        "public_key": pub_pem,
        "registered_at": datetime.utcnow().isoformat()
    }

    save_json(DIR_FILE, directory)
    
    # Atualiza flag
    clients_data[cid]["published"] = True
    save_clients()
    
    return {
        "status": "public key published",
        "public_key": pub_pem[:200] + "..."  # Primeiros 100 caracteres
    }

@app.route("/client/<cid>/request_key/<peer>", methods=["GET"])
def request_key(cid, peer):
    """Solicita chave pública de outro cliente"""
    if peer not in directory:
        return {"error": f"Cliente {peer} não registado"}, 400
    
    public_key = directory[peer]["public_key"]
    
    return {
        "peer": peer,
        "public_key": public_key,
        "registered_at": directory[peer]["registered_at"]
    }

@app.route("/client/<cid>/derive/<peer>", methods=["POST"])
def derive(cid, peer):
    """Deriva chave de sessão usando ECDH"""
    if peer not in directory:
        return {"error": f"Cliente {peer} não registado"}, 400
    
    # Verifica se já tem sessão válida
    if is_session_valid(cid, peer):
        return {"status": "Sessão já existe e é válida"}
    
    keys = get_client_keys(cid)
    if not keys or "priv" not in keys:
        return {"error": "Cliente não possui chave privada"}, 400
    
    peer_pub = crypto.load_public(directory[peer]["public_key"])
    key = crypto.derive_session(keys["priv"], peer_pub)

    sessions[(cid, peer)] = key
    sessions[(peer, cid)] = key
    
    # Salva informação da sessão com timestamp
    session_id = f"{cid}_{peer}"
    session_keys_data[session_id] = {
        "generated_at": datetime.utcnow().isoformat(),
        "valid_until": (datetime.utcnow() + timedelta(minutes=30)).isoformat(),
        "participants": [cid, peer]
    }
    save_session_keys()

    return {"status": "session derived", "key_generated": datetime.utcnow().isoformat()}

# =====================
# Diretório (AR)
# =====================
@app.route("/directory/list")
def list_clients():
    """Lista todos os clientes registados"""
    return {"clients": list(directory.keys())}

@app.route("/directory/info/<cid>")
def get_client_info(cid):
    """Obtém informações de um cliente específico"""
    if cid not in directory:
        return {"error": "Cliente não encontrado"}, 404
    return directory[cid]

@app.route("/clients/list")
def list_all_clients():
    """Lista todos os clientes criados (mesmo sem chaves públicas)"""
    client_info = []
    for cid, data in clients_data.items():
        client_info.append({
            "id": cid,
            "has_keys": data.get("has_keys", False),
            "published": data.get("published", False),
            "created_at": data.get("created_at")
        })
    return {"clients": client_info}

# =====================
# Mensagens
# =====================
@app.route("/send", methods=["POST"])
def send():
    """Envia mensagem cifrada com assinatura digital"""
    data = request.json
    sender = data["from"]
    receiver = data["to"]
    
    # Verifica se existe sessão válida
    if not is_session_valid(sender, receiver):
        return {"error": "Sessão não existe ou expirou. Derive nova chave."}, 400
    
    key = sessions.get((sender, receiver))
    if not key:
        return {"error": "Sessão não derivada"}, 400

    # Cifra a mensagem
    nonce, cipher = crypto.encrypt(key, data["msg"])
    
    # Assina a mensagem
    signature = None
    keys = get_client_keys(sender)
    if keys and "priv" in keys:
        signature = crypto.sign_message(keys["priv"], cipher)

    msg = {
        "from": sender,
        "to": receiver,
        "nonce": nonce,
        "cipher": cipher,
        "signature": signature,
        "timestamp": datetime.utcnow().isoformat()
    }

    messages.append(msg)
    intruder_logs.append(msg)

    save_json(MSG_FILE, messages)
    save_json(INTRUDER_FILE, intruder_logs)

    return {"cipher": cipher, "signature": signature}

@app.route("/receive/<cid>")
def receive(cid):
    """Recebe e decifra mensagem, verificando assinatura"""
    for m in messages:
        if m["to"] == cid:
            key = sessions.get((m["from"], cid))
            if not key:
                continue
            
            # Verifica assinatura
            signature_valid = False
            if m.get("signature") and m["from"] in directory:
                sender_pub = crypto.load_public(directory[m["from"]]["public_key"])
                signature_valid = crypto.verify_signature(
                    sender_pub, 
                    m["cipher"], 
                    m["signature"]
                )
            
            # Decifra
            clear = crypto.decrypt(key, m["nonce"], m["cipher"])

            messages.remove(m)
            save_json(MSG_FILE, messages)

            return {
                "from": m["from"],
                "cipher": m["cipher"],
                "clear": clear,
                "signature_valid": signature_valid,
                "timestamp": m["timestamp"]
            }

    return {"status": "Sem mensagens"}

# =====================
# Rotação de chaves
# =====================
@app.route("/session/rotate/<cid>/<peer>", methods=["POST"])
def rotate_session(cid, peer):
    """Rota a chave de sessão"""
    # Deriva nova chave
    if peer not in directory:
        return {"error": f"Cliente {peer} não registado"}, 400
    
    keys = get_client_keys(cid)
    if not keys or "priv" not in keys:
        return {"error": "Cliente não possui chave privada"}, 400
    
    peer_pub = crypto.load_public(directory[peer]["public_key"])
    new_key = crypto.derive_session(keys["priv"], peer_pub)
    
    # Atualiza sessão
    sessions[(cid, peer)] = new_key
    sessions[(peer, cid)] = new_key
    
    # Atualiza timestamp da sessão
    session_id = f"{cid}_{peer}"
    session_keys_data[session_id] = {
        "generated_at": datetime.utcnow().isoformat(),
        "valid_until": (datetime.utcnow() + timedelta(minutes=30)).isoformat(),
        "participants": [cid, peer]
    }
    save_session_keys()
    
    return {"status": "Chave de sessão rotacionada", "rotated_at": datetime.utcnow().isoformat()}

@app.route("/session/check/<cid>/<peer>", methods=["GET"])
def check_session(cid, peer):
    """Verifica se a sessão é válida"""
    valid = is_session_valid(cid, peer)
    
    if valid:
        session_id = f"{cid}_{peer}"
        session_info = session_keys_data[session_id]
        return {
            "valid": True,
            "generated_at": session_info["generated_at"],
            "valid_until": session_info["valid_until"]
        }
    else:
        return {"valid": False}

# =====================
# Intruso
# =====================
@app.route("/intruder/logs")
def intruder_logs_view():
    """Visualiza todas as mensagens interceptadas"""
    return {"logs": intruder_logs}

@app.route("/intruder/clear", methods=["POST"])
def intruder_clear():
    """Limpa logs do intruso"""
    global intruder_logs
    intruder_logs = []
    save_json(INTRUDER_FILE, intruder_logs)
    return {"status": "Logs limpos"}

# =====================
# Estatísticas
# =====================
@app.route("/stats")
def stats():
    """Retorna estatísticas do sistema"""
    valid_sessions = 0
    for session_id in session_keys_data:
        if is_session_valid(*session_id.split("_")):
            valid_sessions += 1
    
    return {
        "total_clients": len(directory),
        "created_clients": len(clients_data),
        "active_sessions": valid_sessions,
        "messages_in_transit": len(messages),
        "intercepted_messages": len(intruder_logs),
        "expired_sessions": len(session_keys_data) - valid_sessions
    }

# =====================
# Inicialização
# =====================
def init_system():
    """Inicializa o sistema carregando clientes persistidos"""
    print("=" * 60)
    print("  Sistema de Mensagens Seguras Inicializando...")
    print("=" * 60)
    
    # Carrega clientes do disco
    if clients_data:
        print(f"\n📦 Clientes encontrados: {len(clients_data)}")
        for cid, data in clients_data.items():
            has_keys = data.get("has_keys", False)
            published = data.get("published", False)
            
            status = "🔑 Com chaves" if has_keys else "⚪ Sem chaves"
            if published:
                status += " + 📤 Publicado"
            
            print(f"   👤 {cid}: {status}")
            
            # Carrega chaves no cache se existirem
            if has_keys:
                get_client_keys(cid)
    else:
        print("\n📭 Nenhum cliente encontrado")
    
    # Carrega diretório
    if directory:
        print(f"\n🏛️ Autoridade de Registo: {len(directory)} chaves públicas")
    
    # Carrega mensagens
    if messages:
        print(f"\n📨 Mensagens em trânsito: {len(messages)}")
    
    if intruder_logs:
        print(f"🕵️ Mensagens interceptadas: {len(intruder_logs)}")
    
    # Carrega sessões
    if session_keys_data:
        valid_sessions = sum(1 for sid in session_keys_data if is_session_valid(*sid.split("_")))
        print(f"\n🔗 Sessões: {len(session_keys_data)} total, {valid_sessions} válidas")
    
    print("\n" + "=" * 60)
    print("  ✅ Sistema pronto!")
    print("  🌐 Aceder: http://localhost:5000")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    init_system()
    app.run(debug=True, host="0.0.0.0", port=5000)