import streamlit as st
import pandas as pd
import plotly.express as px
import os, hashlib, base64
from datetime import date

st.set_page_config(page_title="Inversiones tu futuro", page_icon="♦️", layout="centered")
USUARIOS_ADMIN = ["jandro", "admin"]
CLAVE_SESION = "inv_futuro_2026"

def obtener_fondo():
    for n in ["fondo.jpg", "fondo.png", "fondo.jpeg", "fondo.webp"]:
        if os.path.exists(n):
            with open(n, "rb") as f:
                data = base64.b64encode(f.read()).decode()
            return f"url('data:image/{n.split('.')[-1]};base64,{data}')"
    return "none"

st.markdown("""<style>
.stApp,[data-testid="stAppViewContainer"],[data-testid="stHeader"]{background-color:#08080A!important;color:#FFF!important}
.block-container{max-width:460px;padding-top:1rem;padding-bottom:3rem}
.fala-brand{background:#111116;padding:10px 14px;border-radius:12px;border-bottom:2px solid #D50000;font-size:1.05rem;font-weight:800;color:#FF1744}
[data-testid="stPopover"]>button{background:#16161D!important;color:#FFF!important;border:1px solid #D50000!important;border-radius:12px!important;font-weight:700!important;height:44px!important;width:100%!important}
[data-testid="stPopoverBody"]{background:#14141B!important;border:1px solid #FF1744!important;border-radius:14px!important;color:#FFF!important}
.grid-card{background:linear-gradient(145deg,#16161D,#0F0F14);border:1px solid #282834;border-radius:18px;padding:16px 10px;text-align:center;margin-bottom:6px}
.cat-mini{background:#14141A;border:1px solid #262630;border-top:3px solid #D50000;border-radius:14px;padding:10px 6px;text-align:center}
.panel{background:#121217;border:1px solid #262632;border-radius:16px;padding:16px;margin-top:12px}
.stButton>button,.stFormSubmitButton>button{background:#D50000!important;color:#FFF!important;border:none!important;border-radius:12px!important;font-weight:700!important;height:42px!important}
input,select,textarea,[data-baseweb="select"]>div{background:#16161C!important;color:#FFF!important;border-color:#2E2E38!important;border-radius:12px!important}
</style>""", unsafe_allow_html=True)

ARCHIVO_U = "usuarios.csv"
def hash_txt(t): return hashlib.sha256(t.encode()).hexdigest()
def token_u(u): return hashlib.sha256(f"{u}:{CLAVE_SESION}".encode()).hexdigest()[:16]
def pesos(v): return f"${v:,.0f}".replace(",", ".")

def cargar_u():
    return pd.read_csv(ARCHIVO_U) if os.path.exists(ARCHIVO_U) else pd.DataFrame(columns=["usuario", "clave_hash"])

def guardar_u(u, c):
    df = cargar_u()
    if u in df["usuario"].values: return False
    df = pd.concat([df, pd.DataFrame([{"usuario": u, "clave_hash": hash_txt(c)}])], ignore_index=True)
    df.to_csv(ARCHIVO_U, index=False)
    return True

if "usuario_activo" not in st.session_state:
    st.session_state.usuario_activo = None
    up, tp = st.query_params.get("u", ""), st.query_params.get("t", "")
    if up and tp == token_u(up) and up in cargar_u()["usuario"].values:
        st.session_state.usuario_activo = up

if "vista_c" not in st.session_state: st.session_state.vista_c = "resumen"
if "vista_a" not in st.session_state: st.session_state.vista_a = "global"

def login_ok(u):
    st.session_state.usuario_activo = u
    st.query_params["u"] = u
    st.query_params["t"] = token_u(u)

def logout():
    st.session_state.usuario_activo = None
    st.session_state.vista_c = "resumen"
    st.session_state.vista_a = "global"
    st.query_params.clear()

user = st.session_state.usuario_activo

# ==========================================
# 1. SI NO HAY SESIÓN -> PANTALLA LOGIN
# ==========================================
if user is None:
    fondo = obtener_fondo()
    if fondo != "none":
        st.markdown(f"<style>[data-testid='stAppViewContainer']{{background-image:linear-gradient(rgba(8,8,10,0.65),rgba(8,8,10,0.85)),{fondo}!important;background-size:cover!important;background-position:center!important}}</style>", unsafe_allow_html=True)
    st.markdown("<style>[data-testid='stForm']{background:rgba(18,18,24,0.88)!important;border:1px solid rgba(255,23,68,0.45)!important;border-radius:16px!important;padding:20px!important}</style>", unsafe_allow_html=True)
    st.markdown('<div style="background:linear-gradient(135deg,#D50000,#7F0000);padding:20px;border-radius:18px;text-align:center;margin-bottom:16px;border:1px solid #FF1744;"><h2 style="margin:0;color:#FFF;">♦️ Inversiones tu futuro</h2><p style="margin:4px 0 0;color:#FFCDD2;font-size:0.88rem;">Tu plataforma financiera en un solo lugar</p></div>', unsafe_allow_html=True)

    t1, t2 = st.tabs(["🔑 Iniciar Sesión", "📝 Crear Cuenta"])
    with t1:
        with st.form("f_log"):
            u_in = st.text_input("Usuario").strip().lower()
            p_in = st.text_input("Contraseña", type="password")
            if st.form_submit_button("Ingresar", use_container_width=True):
                dfu = cargar_u()
                if not dfu[(dfu["usuario"] == u_in) & (dfu["clave_hash"] == hash_txt(p_in))].empty:
                    login_ok(u_in)
                    st.rerun()
                else:
                    st.error("Usuario o contraseña incorrectos.")
    with t2:
        with st.form("f_reg"):
            nu = st.text_input("Elige tu usuario").strip().lower()
            np1 = st.text_input("Crea una contraseña", type="password")
            np2 = st.text_input("Repite tu contraseña", type="password")
            if st.form_submit_button("Registrarme", use_container_width=True):
                if not nu or not np1: st.warning("Completa todos los campos.")
                elif np1 != np2: st.error("Las contraseñas no coinciden.")
                elif guardar_u(nu, np1): st.success("¡Cuenta creada! Inicia sesión al lado.")
                else: st.error("Ese usuario ya existe.")

# ==========================================
# 2. SI ES CLIENTE -> INTERFAZ FALABELLA
# ==========================================
elif user not in USUARIOS_ADMIN:
    ADATOS = f"movimientos_{user}.csv"
    df = pd.read_csv(ADATOS) if os.path.exists(ADATOS) else pd.DataFrame(columns=["Fecha", "Tipo", "Categoria", "Descripcion", "Monto"])

    c_izq, c_der = st.columns([2.6, 1.4])
    with c_izq: st.markdown('<div class="fala-brand">☰ Inversiones tu futuro ♦️</div>', unsafe_allow_html=True)
    with c_der:
        with st.popover(f"👤 {user.capitalize()}", use_container_width=True):
            st.caption("Cuenta Cliente")
            st.button("🚪 Cerrar Sesión", key="out_cli", on_click=logout, use_container_width=True)

    bmov = st.text_input("", placeholder="🔍 Buscar movimiento o categoría...", label_visibility="collapsed").strip().lower()
    ing = df[df["Tipo"] == "Ingreso"]["Monto"].sum()
    gas = df[df["Tipo"] == "Gasto"]["Monto"].sum()
    inv = df[df["Tipo"] == "Inversión"]["Monto"].sum()
    sal = ing - gas - inv

    st.markdown("<h4 style='margin:6px 0 2px'>Nuestros servicios</h4><p style='font-size:0.8rem;color:#9E9EA8;margin-bottom:10px'>Lo mejor de tu cartera en un solo lugar</p>", unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(f'<div class="grid-card"><div style="font-size:2rem">💵</div><b>Mi Saldo</b><br><span style="color:#FF5252;font-size:0.8rem">{pesos(sal)}</span></div>', unsafe_allow_html=True)
        if st.button("Movimientos", key="c1", use_container_width=True): st.session_state.vista_c = "resumen"
    with c2:
        st.markdown(f'<div class="grid-card"><div style="font-size:2rem">🚀</div><b>Invertir</b><br><span style="color:#FF5252;font-size:0.8rem">{pesos(inv)}</span></div>', unsafe_allow_html=True)
        if st.button("Nueva Inversión", key="c2", use_container_width=True): st.session_state.vista_c = "invertir"

    c3, c4 = st.columns(2)
    with c3:
        st.markdown('<div class="grid-card"><div style="font-size:2rem">💸</div><b>Anotar Flujo</b><br><span style="color:#FF5252;font-size:0.8rem">Ingreso / Gasto</span></div>', unsafe_allow_html=True)
        if st.button("Registrar", key="c3", use_container_width=True): st.session_state.vista_c = "anotar"
    with c4:
        st.markdown('<div class="grid-card"><div style="font-size:2rem">📊</div><b>Portafolio</b><br><span style="color:#FF5252;font-size:0.8rem">Gráficos</span></div>', unsafe_allow_html=True)
        if st.button("Ver Gráficos", key="c4", use_container_width=True): st.session_state.vista_c = "portafolio"

    m1, m2, m3 = st.columns(3)
    with m1: st.markdown(f'<div class="cat-mini">🏦<br><span style="font-size:0.72rem;color:#9E9EA8">Ingresos</span><br><b style="color:#00E676;font-size:0.8rem">{pesos(ing)}</b></div>', unsafe_allow_html=True)
    with m2: st.markdown(f'<div class="cat-mini">📈<br><span style="font-size:0.72rem;color:#9E9EA8">Invertido</span><br><b style="color:#FF5252;font-size:0.8rem">{pesos(inv)}</b></div>', unsafe_allow_html=True)
    with m3: st.markdown(f'<div class="cat-mini">🛒<br><span style="font-size:0.72rem;color:#9E9EA8">Gastos</span><br><b style="font-size:0.8rem">{pesos(gas)}</b></div>', unsafe_allow_html=True)

    st.markdown('<div class="panel">', unsafe_allow_html=True)
    if st.session_state.vista_c == "resumen":
        st.subheader("📋 Historial")
        if not df.empty:
            dfs = df.iloc[::-1]
            if bmov: dfs = dfs[dfs["Categoria"].str.lower().str.contains(bmov) | dfs["Tipo"].str.lower().str.contains(bmov)]
            for i, r in dfs.iterrows():
                brd = "#00E676" if r["Tipo"] == "Ingreso" else ("#FF1744" if r["Tipo"] == "Inversión" else "#616161")
                sig = "+" if r["Tipo"] == "Ingreso" else "-"
                cm = "#00E676" if r["Tipo"] == "Ingreso" else ("#FF5252" if r["Tipo"] == "Inversión" else "#FFF")
                dsc = r["Descripcion"] if pd.notna(r["Descripcion"]) and r["Descripcion"] != "" else r["Tipo"]
