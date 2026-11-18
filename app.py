
import streamlit as st
import sqlite3
import hashlib
import hmac
import secrets
import plotly.express as px
import pandas as pd
from datetime import datetime
import os
import uuid
import base64

st.set_page_config(
    page_title="Mi Banco • Inversiones Tu Futuro",
    page_icon="♦️",
    layout="centered"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "cartera_usuarios.db")
CARPETA_COMPROBANTES = os.path.join(BASE_DIR, "comprobantes_subidos")
NOMBRE_IMAGEN_FONDO = "fondo_banco.jpg"

os.makedirs(CARPETA_COMPROBANTES, exist_ok=True)

ADMIN_USER = "jandro"
ADMIN_PASS = "admin123"

PREGUNTAS_SEGURIDAD = [
    "¿Cómo se llamaba tu primera mascota?",
    "¿En qué ciudad naciste?",
    "¿Cuál era el nombre de tu colegio?",
    "¿Cuál es el segundo nombre de tu madre?",
    "¿Cuál era tu apodo de infancia?",
    "¿Cuál es tu comida favorita?",
    "¿Cuál fue tu primer trabajo?"
]


# =====================================================
# BASE DE DATOS
# =====================================================

def init_db():
    conexion = sqlite3.connect(
        DB_PATH,
        timeout=30,
        check_same_thread=False
    )
    conexion.execute("PRAGMA busy_timeout = 30000")

    c = conexion.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            rol TEXT NOT NULL,
            saldo REAL DEFAULT 0.0,
            baneado INTEGER DEFAULT 0,
            pregunta1 TEXT,
            pregunta2 TEXT,
            respuesta1_hash TEXT,
            respuesta2_hash TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS transacciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            tipo TEXT,
            monto REAL,
            fecha TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS comprobantes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            titulo TEXT,
            imagen_path TEXT,
            fecha TEXT,
            leido INTEGER DEFAULT 0
        )
    """)

    columnas = [
        fila[1] for fila in c.execute(
            "PRAGMA table_info(usuarios)"
        ).fetchall()
    ]

    nuevas_columnas = {
        "baneado": "INTEGER DEFAULT 0",
        "pregunta1": "TEXT",
        "pregunta2": "TEXT",
        "respuesta1_hash": "TEXT",
        "respuesta2_hash": "TEXT"
    }

    for nombre, tipo in nuevas_columnas.items():
        if nombre not in columnas:
            c.execute(
                f"ALTER TABLE usuarios ADD COLUMN {nombre} {tipo}"
            )

    columnas_comprobantes = [
        fila[1] for fila in c.execute(
            "PRAGMA table_info(comprobantes)"
        ).fetchall()
    ]

    if "imagen_path" not in columnas_comprobantes:
        c.execute(
            "ALTER TABLE comprobantes ADD COLUMN imagen_path TEXT"
        )

    if "leido" not in columnas_comprobantes:
        c.execute(
            "ALTER TABLE comprobantes ADD COLUMN leido INTEGER DEFAULT 0"
        )

    admin_hash = hashlib.sha256(ADMIN_PASS.encode()).hexdigest()

    c.execute("""
        INSERT OR IGNORE INTO usuarios
        (username, password, rol, saldo, baneado)
        VALUES (?, ?, 'admin', 0.0, 0)
    """, (ADMIN_USER, admin_hash))

    c.execute("""
        UPDATE usuarios
        SET baneado = 0
        WHERE username = ? AND rol = 'admin'
    """, (ADMIN_USER,))

    conexion.commit()
    return conexion


conn = init_db()


# =====================================================
# SEGURIDAD Y CONTRASEÑAS
# =====================================================

def hash_pass(password):
    return hashlib.sha256(password.encode()).hexdigest()


def normalizar_respuesta(respuesta):
    return " ".join(respuesta.strip().casefold().split())


def hash_respuesta(respuesta):
    salt = secrets.token_bytes(16)

    resultado = hashlib.pbkdf2_hmac(
        "sha256",
        normalizar_respuesta(respuesta).encode(),
        salt,
        200000
    )

    return salt.hex() + "$" + resultado.hex()


def verificar_respuesta(respuesta, hash_guardado):
    if not hash_guardado or "$" not in hash_guardado:
        return False

    try:
        salt_hex, hash_original = hash_guardado.split("$", 1)
        salt = bytes.fromhex(salt_hex)

        resultado = hashlib.pbkdf2_hmac(
            "sha256",
            normalizar_respuesta(respuesta).encode(),
            salt,
            200000
        ).hex()

        return hmac.compare_digest(resultado, hash_original)

    except (ValueError, TypeError):
        return False


def obtener_preguntas_usuario(username):
    c = conn.cursor()

    c.execute("""
        SELECT pregunta1, pregunta2
        FROM usuarios
        WHERE username = ?
    """, (username.strip().lower(),))

    return c.fetchone()


def usuario_tiene_preguntas(username):
    preguntas = obtener_preguntas_usuario(username)

    return bool(
        preguntas
        and preguntas[0]
        and preguntas[1]
    )


def guardar_preguntas_seguridad(
    username,
    pregunta1,
    respuesta1,
    pregunta2,
    respuesta2
):
    if not respuesta1.strip() or not respuesta2.strip():
        return False, "Debes completar ambas respuestas."

    if pregunta1 == pregunta2:
        return False, "Debes seleccionar dos preguntas diferentes."

    c = conn.cursor()

    c.execute("""
        UPDATE usuarios
        SET pregunta1 = ?,
            pregunta2 = ?,
            respuesta1_hash = ?,
            respuesta2_hash = ?
        WHERE username = ?
    """, (
        pregunta1,
        pregunta2,
        hash_respuesta(respuesta1),
        hash_respuesta(respuesta2),
        username
    ))

    conn.commit()

    return True, "Preguntas de seguridad guardadas correctamente."


def verificar_recuperacion(username, respuesta1, respuesta2):
    c = conn.cursor()

    c.execute("""
        SELECT respuesta1_hash, respuesta2_hash
        FROM usuarios
        WHERE username = ?
    """, (username.strip().lower(),))

    datos = c.fetchone()

    if not datos or not datos[0] or not datos[1]:
        return False

    return (
        verificar_respuesta(respuesta1, datos[0])
        and verificar_respuesta(respuesta2, datos[1])
    )


def cambiar_password(username, password_actual, password_nueva):
    if len(password_nueva) < 8:
        return False, "La nueva contraseña debe tener al menos 8 caracteres."

    c = conn.cursor()

    c.execute("""
        SELECT password
        FROM usuarios
        WHERE username = ?
    """, (username,))

    datos = c.fetchone()

    if not datos:
        return False, "No se encontró la cuenta."

    if not hmac.compare_digest(
        datos[0],
        hash_pass(password_actual)
    ):
        return False, "La contraseña actual es incorrecta."

    c.execute("""
        UPDATE usuarios
        SET password = ?
        WHERE username = ?
    """, (hash_pass(password_nueva), username))

    conn.commit()

    return True, "Tu contraseña fue cambiada correctamente."


def restablecer_password(username, password_nueva):
    if len(password_nueva) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."

    c = conn.cursor()

    c.execute("""
        UPDATE usuarios
        SET password = ?
        WHERE username = ?
    """, (hash_pass(password_nueva), username.strip().lower()))

    conn.commit()

    return c.rowcount > 0


# =====================================================
# USUARIOS
# =====================================================

def registrar_usuario(
    username,
    password,
    pregunta1,
    respuesta1,
    pregunta2,
    respuesta2
):
    username = username.strip().lower()

    if not username or not password:
        return False, "Completa todos los campos."

    if len(username) < 3:
        return False, "El usuario debe tener al menos 3 caracteres."

    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres."

    if not respuesta1.strip() or not respuesta2.strip():
        return False, "Debes responder las dos preguntas de seguridad."

    if pregunta1 == pregunta2:
        return False, "Selecciona dos preguntas diferentes."

    try:
        c = conn.cursor()

        c.execute("""
            INSERT INTO usuarios (
                username, password, rol, saldo, baneado,
                pregunta1, pregunta2, respuesta1_hash, respuesta2_hash
            )
            VALUES (?, ?, 'cliente', 0.0, 0, ?, ?, ?, ?)
        """, (
            username,
            hash_pass(password),
            pregunta1,
            pregunta2,
            hash_respuesta(respuesta1),
            hash_respuesta(respuesta2)
        ))

        conn.commit()

        return True, "¡Cuenta creada con éxito! Ya puedes iniciar sesión."

    except sqlite3.IntegrityError:
        return False, "Ese nombre de usuario ya existe."


def verificar_login(username, password):
    username = username.strip().lower()

    c = conn.cursor()

    c.execute("""
        SELECT username, rol, saldo, baneado
        FROM usuarios
        WHERE username = ? AND password = ?
    """, (username, hash_pass(password)))

    return c.fetchone()


def obtener_todos_usuarios():
    return pd.read_sql_query("""
        SELECT
            username,
            rol,
            saldo,
            CASE
                WHEN baneado = 1 THEN 'BANEADO'
                ELSE 'ACTIVO'
            END AS estado
        FROM usuarios
        ORDER BY rol, username
    """, conn)


def cambiar_estado_baneo(username, estado):
    if username.lower() == ADMIN_USER:
        return False

    c = conn.cursor()

    c.execute("""
        UPDATE usuarios
        SET baneado = ?
        WHERE username = ? AND rol = 'cliente'
    """, (1 if estado else 0, username))

    conn.commit()
    return c.rowcount > 0


def eliminar_usuario(username):
    if username.lower() == ADMIN_USER:
        return False, "No puedes eliminar la cuenta principal."

    c = conn.cursor()

    c.execute("""
        SELECT username, rol
        FROM usuarios
        WHERE username = ?
    """, (username,))

    usuario = c.fetchone()

    if usuario is None:
        return False, "El usuario no existe."

    if usuario[1] != "cliente":
        return False, "Solo se pueden eliminar cuentas de clientes."

    c.execute("""
        SELECT imagen_path
        FROM comprobantes
        WHERE username = ?
    """, (username,))

    archivos = c.fetchall()

    c.execute(
        "DELETE FROM transacciones WHERE username = ?",
        (username,)
    )

    c.execute(
        "DELETE FROM comprobantes WHERE username = ?",
        (username,)
    )

    c.execute(
        "DELETE FROM usuarios WHERE username = ? AND rol = 'cliente'",
        (username,)
    )

    conn.commit()

    for archivo in archivos:
        ruta = archivo[0]

        if not ruta:
            continue

        try:
            ruta_real = os.path.abspath(ruta)
            carpeta_real = os.path.abspath(CARPETA_COMPROBANTES)

            if os.path.commonpath(
                [ruta_real, carpeta_real]
            ) == carpeta_real:
                if os.path.isfile(ruta_real):
                    os.remove(ruta_real)

        except (OSError, ValueError):
            pass

    return True, "Cuenta eliminada correctamente."


# =====================================================
# TRANSACCIONES
# =====================================================

def registrar_transaccion(username, tipo, monto):
    c = conn.cursor()

    fecha_actual = datetime.now().strftime("%Y-%m-%d %H:%M")

    c.execute("""
        SELECT saldo, baneado
        FROM usuarios
        WHERE username = ?
    """, (username,))

    resultado = c.fetchone()

    if resultado is None:
        return 0.0

    if resultado[1] == 1:
        return float(resultado[0])

    saldo_actual = float(resultado[0])

    if tipo == "Ingreso":
        nuevo_saldo = saldo_actual + monto
    elif tipo == "Retiro":
        nuevo_saldo = max(0.0, saldo_actual - monto)
    else:
        nuevo_saldo = monto

    c.execute("""
        INSERT INTO transacciones
        (username, tipo, monto, fecha)
        VALUES (?, ?, ?, ?)
    """, (username, tipo, monto, fecha_actual))

    c.execute("""
        UPDATE usuarios
        SET saldo = ?
        WHERE username = ?
    """, (nuevo_saldo, username))

    conn.commit()
    return nuevo_saldo


def obtener_historial(username):
    return pd.read_sql_query("""
        SELECT tipo, monto, fecha
        FROM transacciones
        WHERE username = ?
        ORDER BY id DESC
    """, conn, params=(username,))


# =====================================================
# COMPROBANTES
# =====================================================

def enviar_comprobante(username, titulo, imagen_path):
    c = conn.cursor()

    fecha_actual = datetime.now().strftime("%Y-%m-%d %H:%M")

    c.execute("""
        INSERT INTO comprobantes
        (username, titulo, imagen_path, fecha, leido)
        VALUES (?, ?, ?, ?, 0)
    """, (username, titulo, imagen_path, fecha_actual))

    conn.commit()


def obtener_comprobantes(username):
    return pd.read_sql_query("""
        SELECT id, titulo, imagen_path, fecha, leido
        FROM comprobantes
        WHERE username = ?
        ORDER BY id DESC
    """, conn, params=(username,))


def obtener_todos_los_comprobantes():
    return pd.read_sql_query("""
        SELECT id, username, titulo, fecha
        FROM comprobantes
        ORDER BY id DESC
    """, conn)


def marcar_leidos(username):
    c = conn.cursor()

    c.execute("""
        UPDATE comprobantes
        SET leido = 1
        WHERE username = ?
    """, (username,))

    conn.commit()


# =====================================================
# FONDO
# =====================================================

def aplicar_fondo_fijo():
    ruta_imagen = os.path.join(BASE_DIR, NOMBRE_IMAGEN_FONDO)

    if not os.path.isfile(ruta_imagen):
        return

    extension = os.path.splitext(ruta_imagen)[1].lower()

    mime = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".webp": "image/webp",
        ".bmp": "image/bmp"
    }.get(extension, "image/jpeg")

    try:
        with open(ruta_imagen, "rb") as archivo:
            imagen_base64 = base64.b64encode(
                archivo.read()
            ).decode("ascii")

        st.markdown(f"""
            <style>
            .stApp {{
                background:
                linear-gradient(
                    rgba(5, 8, 18, 0.58),
                    rgba(5, 8, 18, 0.72)
                ),
                url("data:{mime};base64,{imagen_base64}")
                center center / cover fixed no-repeat !important;
            }}

            [data-testid="stHeader"] {{
                background: transparent !important;
            }}
            </style>
        """, unsafe_allow_html=True)

    except OSError:
        pass


# =====================================================
# SESIÓN
# =====================================================

if "logueado" not in st.session_state:
    st.session_state.logueado = False
    st.session_state.usuario = None
    st.session_state.rol = None

if "modo_oscuro" not in st.session_state:
    st.session_state.modo_oscuro = True

if "ver_saldo" not in st.session_state:
    st.session_state.ver_saldo = True

if "seccion_cliente" not in st.session_state:
    st.session_state.seccion_cliente = "Resumen"

if "mostrar_recuperacion" not in st.session_state:
    st.session_state.mostrar_recuperacion = False

if "usuario_recuperacion" not in st.session_state:
    st.session_state.usuario_recuperacion = None


def cerrar_sesion():
    st.session_state.logueado = False
    st.session_state.usuario = None
    st.session_state.rol = None
    st.session_state.seccion_cliente = "Resumen"
    st.session_state.mostrar_recuperacion = False
    st.session_state.usuario_recuperacion = None
    st.query_params.clear()
    st.rerun()


# Comprobar que la cuenta siga existiendo y no esté baneada.
if st.session_state.logueado:
    c = conn.cursor()

    c.execute("""
        SELECT rol, baneado
        FROM usuarios
        WHERE username = ?
    """, (st.session_state.usuario,))

    estado_sesion = c.fetchone()

    if (
        estado_sesion is None
        or estado_sesion[1] == 1
        or estado_sesion[0] != st.session_state.rol
    ):
        st.session_state.logueado = False
        st.session_state.usuario = None
        st.session_state.rol = None
        st.session_state.seccion_cliente = "Resumen"
        st.query_params.clear()

        st.warning(
            "Tu sesión ha terminado. Tu cuenta puede haber sido bloqueada o eliminada."
        )


# =====================================================
# ESTILOS
# =====================================================

def aplicar_estilos():

    if st.session_state.modo_oscuro:
        bg_app = "#0B0F19"
        text_color = "#F8FAFC"
        card_bg = "#131B2E"
        card_border = "#1E293B"
        btn_bg = "linear-gradient(145deg, #1A233A, #111827)"
        btn_border = "#2A374E"

    else:
        bg_app = "#F8FAFC"
        text_color = "#0F172A"
        card_bg = "#FFFFFF"
        card_border = "#E2E8F0"
        btn_bg = "linear-gradient(145deg, #FFFFFF, #F1F5F9)"
        btn_border = "#CBD5E1"

    st.markdown(f"""
        <style>
        .stApp {{
            background-color: {bg_app} !important;
            color: {text_color} !important;
            font-family: -apple-system, BlinkMacSystemFont,
            "Segoe UI", Roboto, sans-serif;
        }}

        #MainMenu {{visibility: hidden;}}
        footer {{visibility: hidden;}}
        header {{visibility: hidden;}}

        div[data-testid="stVerticalBlockBorderWrapper"] {{
            background-color: {card_bg} !important;
            border: 1px solid {card_border} !important;
            border-radius: 20px !important;
            padding: 16px !important;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1) !important;
            margin-bottom: 20px !important;
        }}

        .banner-banco {{
            background: linear-gradient(135deg, #E63946, #780000);
            padding: 26px;
            border-radius: 20px;
            text-align: center;
            margin-bottom: 20px;
            box-shadow: 0 10px 25px rgba(230,57,70,0.35);
        }}

        .banner-banco h1 {{
            color: #FFFFFF !important;
            font-size: 32px;
            margin: 0;
            font-weight: 800;
            letter-spacing: 1px;
        }}

        .banner-banco .subtitulo-futuro {{
            color: #F1FAEE !important;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 3px;
            margin-top: 6px;
            opacity: 0.85;
            font-weight: 500;
        }}

        .saldo-elegante {{
            font-family: Georgia, serif;
            font-size: 36px;
            font-weight: bold;
            color: #10B981;
            letter-spacing: 0.5px;
            text-shadow: 0 2px 10px rgba(16,185,129,0.25);
        }}

        .alerta-notif {{
            background: linear-gradient(135deg, #E63946, #9B2226);
            color: white;
            padding: 12px;
            border-radius: 14px;
            font-weight: bold;
            margin-bottom: 15px;
            text-align: center;
        }}

        .admin-identidad {{
            background: linear-gradient(135deg, #171D2D, #090D17);
            border: 1px solid rgba(212,175,55,0.45);
            border-radius: 22px;
            padding: 25px 15px;
            text-align: center;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.25);
        }}

        .admin-corona {{
            font-size: 42px;
            line-height: 1.2;
            margin-bottom: 5px;
            filter: drop-shadow(0 0 8px rgba(255,193,7,0.5));
        }}

        .admin-nombre {{
            color: #F5D778 !important;
            font-size: 32px;
            font-weight: 900;
            letter-spacing: 5px;
            margin: 0;
        }}

        .admin-etiqueta {{
            color: #D6B85A !important;
            font-size: 10px;
            letter-spacing: 4px;
            font-weight: 700;
            margin-top: 7px;
        }}

        .stButton > button {{
            background: {btn_bg} !important;
            border: 1px solid {btn_border} !important;
            color: {text_color} !important;
            border-radius: 16px !important;
            font-weight: 600 !important;
            font-size: 13px !important;
            height: 95px !important;
            width: 100% !important;
            box-shadow: 0 6px 16px rgba(0,0,0,0.1) !important;
            transition: all 0.2s ease-in-out !important;
        }}

        .stButton > button:hover {{
            background: linear-gradient(145deg, #E63946, #9B2226) !important;
            border-color: #E63946 !important;
            color: #FFFFFF !important;
            box-shadow: 0 10px 22px rgba(230,57,70,0.4) !important;
            transform: translateY(-3px) !important;
        }}

        div[data-testid="stFormSubmitButton"] button {{
            height: 48px !important;
        }}

        </style>
    """, unsafe_allow_html=True)


aplicar_estilos()


# =====================================================
# PANTALLA DE ACCESO
# =====================================================

if not st.session_state.logueado:

    aplicar_fondo_fijo()

    st.markdown("""
        <div class="banner-banco">
            <h1>Mi Banco</h1>
            <div class="subtitulo-futuro">
                Inversiones Tu Futuro
            </div>
        </div>
    """, unsafe_allow_html=True)

    tab_login, tab_registro = st.tabs([
        "🔑 Iniciar Sesión",
        "📝 Crear Cuenta"
    ])

    # ---------------------------------------------
    # INICIAR SESIÓN
    # ---------------------------------------------

    with tab_login:

        with st.container(border=True):

            with st.form("login_form"):

                user_input = st.text_input("Usuario")

                pass_input = st.text_input(
                    "Contraseña",
                    type="password"
                )

                submit_btn = st.form_submit_button(
                    "Ingresar",
                    use_container_width=True
                )

                if submit_btn:

                    user_data = verificar_login(
                        user_input,
                        pass_input
                    )

                    if user_data:

                        if user_data[3] == 1:
                            st.error(
                                "🚫 Tu cuenta ha sido baneada. Contacta con la administración."
                            )

                        else:
                            st.session_state.logueado = True
                            st.session_state.usuario = user_data[0]
                            st.session_state.rol = user_data[1]
                            st.session_state.mostrar_recuperacion = False
                            st.rerun()

                    else:
                        st.error("⚠️ Usuario o contraseña incorrectos.")

    # ---------------------------------------------
    # CREAR CUENTA
    # ---------------------------------------------

    with tab_registro:

        with st.container(border=True):

            st.subheader("Crear una cuenta")

            st.info(
                "Para proteger tu cuenta, debes registrar dos preguntas de seguridad. "
                "Las necesitarás si algún día olvidas tu contraseña."
            )

            with st.form("registro_form"):

                new_user_input = st.text_input("Nuevo Usuario")

                new_pass_input = st.text_input(
                    "Nueva Contraseña",
                    type="password",
                    help="Mínimo 8 caracteres."
                )

                confirmar_pass = st.text_input(
                    "Confirmar Contraseña",
                    type="password"
                )

                st.divider()

                st.markdown("**🔐 Primera pregunta de seguridad**")

                pregunta_registro1 = st.selectbox(
                    "Selecciona tu primera pregunta",
                    PREGUNTAS_SEGURIDAD,
                    key="pregunta_registro1"
                )

                respuesta_registro1 = st.text_input(
                    "Escribe tu respuesta",
                    type="password"
                )

                st.markdown("**🔐 Segunda pregunta de seguridad**")

                pregunta_registro2 = st.selectbox(
                    "Selecciona tu segunda pregunta",
                    PREGUNTAS_SEGURIDAD,
                    index=1,
                    key="pregunta_registro2"
                )

                respuesta_registro2 = st.text_input(
                    "Escribe tu segunda respuesta",
                    type="password"
                )

                reg_btn = st.form_submit_button(
                    "Crear mi cuenta",
                    use_container_width=True
                )

                if reg_btn:

                    if new_pass_input != confirmar_pass:
                        st.error("Las contraseñas no coinciden.")

                    else:
                        exito, mensaje = registrar_usuario(
                            new_user_input,
                            new_pass_input,
                            pregunta_registro1,
                            respuesta_registro1,
                            pregunta_registro2,
                            respuesta_registro2
                        )

                        if exito:
                            st.success(mensaje)
                        else:
                            st.error(mensaje)

    # =================================================
    # BOTÓN DE RECUPERACIÓN GLOBAL
    # ESTÁ FUERA DE LAS DOS PESTAÑAS
    # =================================================

    st.divider()

    with st.container(border=True):

        st.markdown(
            "<div style='text-align:center;'>"
            "<p style='font-size:16px; font-weight:700; margin-bottom:8px;'>"
            "¿Olvidaste tu contraseña?"
            "</p>"
            "<p style='font-size:13px; opacity:0.8;'>"
            "Puedes recuperar el acceso respondiendo tus preguntas de seguridad."
            "</p>"
            "</div>",
            unsafe_allow_html=True
        )

        if st.button(
            "🔐 RECUPERAR MI CONTRASEÑA",
            use_container_width=True,
            key="abrir_recuperacion_global"
        ):
            st.session_state.mostrar_recuperacion = True
            st.session_state.usuario_recuperacion = None
            st.rerun()

    # ---------------------------------------------
    # RECUPERACIÓN DE CONTRASEÑA
    # ---------------------------------------------

    if st.session_state.mostrar_recuperacion:

        st.divider()

        with st.container(border=True):

            st.subheader("🔐 Recuperar contraseña")

            st.write(
                "Recupera el acceso a tu cuenta respondiendo "
                "las preguntas de seguridad que registraste."
            )

            if st.button(
                "← Volver al inicio de sesión",
                key="volver_login"
            ):
                st.session_state.mostrar_recuperacion = False
                st.session_state.usuario_recuperacion = None
                st.rerun()

            with st.form("buscar_usuario_recuperacion"):

                usuario_busqueda = st.text_input(
                    "Escribe tu nombre de usuario",
                    key="usuario_busqueda_rec"
                )

                buscar_btn = st.form_submit_button(
                    "Continuar",
                    use_container_width=True
                )

                if buscar_btn:

                    usuario_busqueda = usuario_busqueda.strip().lower()

                    c = conn.cursor()

                    c.execute("""
                        SELECT username, baneado, pregunta1, pregunta2
                        FROM usuarios
                        WHERE username = ?
                    """, (usuario_busqueda,))

                    datos = c.fetchone()

                    if not datos:
                        st.error("No encontramos esa cuenta.")

                    elif datos[1] == 1:
                        st.error(
                            "Esta cuenta está baneada. Contacta con la administración."
                        )

                    elif not datos[2] or not datos[3]:
                        st.warning(
                            "Esta cuenta todavía no tiene preguntas de seguridad. "
                            "Si es una cuenta antigua, inicia sesión y configúralas "
                            "en el apartado Configuración."
                        )

                    else:
                        st.session_state.usuario_recuperacion = datos[0]
                        st.rerun()

            usuario_rec = st.session_state.usuario_recuperacion

            if usuario_rec:

                c = conn.cursor()

                c.execute("""
                    SELECT pregunta1, pregunta2, baneado
                    FROM usuarios
                    WHERE username = ?
                """, (usuario_rec,))

                datos_preguntas = c.fetchone()

                if datos_preguntas and datos_preguntas[2] == 0:

                    st.divider()

                    st.success(
                        f"Cuenta encontrada: {usuario_rec}"
                    )

                    with st.form("form_respuestas_recuperacion"):

                        st.markdown(
                            f"**1. {datos_preguntas[0]}**"
                        )

                        respuesta1_rec = st.text_input(
                            "Primera respuesta",
                            type="password"
                        )

                        st.markdown(
                            f"**2. {datos_preguntas[1]}**"
                        )

                        respuesta2_rec = st.text_input(
                            "Segunda respuesta",
                            type="password"
                        )

                        st.divider()

                        nueva_pass_rec = st.text_input(
                            "Nueva contraseña",
                            type="password"
                        )

                        confirmar_pass_rec = st.text_input(
                            "Confirmar nueva contraseña",
                            type="password"
                        )

                        restablecer_btn = st.form_submit_button(
                            "Restablecer contraseña",
                            use_container_width=True
                        )

                        if restablecer_btn:

                            if nueva_pass_rec != confirmar_pass_rec:
                                st.error("Las contraseñas no coinciden.")

                            elif len(nueva_pass_rec) < 8:
                                st.error(
                                    "La contraseña debe tener al menos 8 caracteres."
                                )

                            elif not verificar_recuperacion(
                                usuario_rec,
                                respuesta1_rec,
                                respuesta2_rec
                            ):
                                st.error(
                                    "Las respuestas de seguridad son incorrectas."
                                )

                            else:
                                exito = restablecer_password(
                                    usuario_rec,
                                    nueva_pass_rec
                                )

                                if exito:
                                    st.session_state.usuario_recuperacion = None
                                    st.session_state.mostrar_recuperacion = False

                                    st.success(
                                        "¡Contraseña actualizada! "
                                        "Ya puedes iniciar sesión con tu nueva contraseña."
                                    )

                                else:
                                    st.error(
                                        "No se pudo actualizar la contraseña."
                                    )


# =====================================================
# PANEL PRINCIPAL
# =====================================================

else:

    es_admin = st.session_state.rol == "admin"
    usuario_actual = st.session_state.usuario

    cursor = conn.cursor()

    cursor.execute("""
        SELECT saldo
        FROM usuarios
        WHERE username = ?
    """, (usuario_actual,))

    resultado_saldo = cursor.fetchone()

    saldo_cliente = (
        float(resultado_saldo[0])
        if resultado_saldo else 0.0
    )

    df_comps = obtener_comprobantes(usuario_actual)

    no_leidas = (
        int((df_comps["leido"] == 0).sum())
        if not df_comps.empty else 0
    )

    df_hist = obtener_historial(usuario_actual)

    if es_admin:

        st.markdown("""
            <div class="admin-identidad">
                <div class="admin-corona">👑</div>
                <div class="admin-nombre">JANDRO</div>
                <div class="admin-etiqueta">ADMINISTRADOR</div>
            </div>
        """, unsafe_allow_html=True)

        st.caption(
            f"Sesión de administrador: **{usuario_actual}**"
        )

    else:
        st.title(f"👋 Hola, {usuario_actual}")

    col_control1, col_control2 = st.columns(2)

    with col_control1:

        modo_label = (
            "☀️ Modo Claro"
            if st.session_state.modo_oscuro
            else "🌙 Modo Oscuro"
        )

        if st.button(
            modo_label,
            use_container_width=True,
            key="modo_dashboard"
        ):
            st.session_state.modo_oscuro = (
                not st.session_state.modo_oscuro
            )
            st.rerun()

    with col_control2:

        if st.button(
            "🚪 Cerrar Sesión",
            use_container_width=True,
            key="logout_dashboard"
        ):
            cerrar_sesion()

    if no_leidas > 0:

        st.markdown(f"""
            <div class="alerta-notif">
                🔔 Tienes {no_leidas} comprobante(s) nuevo(s).
                Revisa la sección Comprobantes.
            </div>
        """, unsafe_allow_html=True)

    st.divider()

    with st.container(border=True):

        col_saldo1, col_saldo2 = st.columns([3, 1])

        with col_saldo1:

            st.markdown(
                "<p style='opacity:0.7; margin-bottom:2px; "
                "font-size:12px; text-transform:uppercase; "
                "letter-spacing:0.5px;'>"
                "Balance Total Disponible</p>",
                unsafe_allow_html=True
            )

            if st.session_state.ver_saldo:

                st.markdown(
                    f"<div class='saldo-elegante'>"
                    f"${saldo_cliente:,.2f}</div>",
                    unsafe_allow_html=True
                )

            else:

                st.markdown(
                    "<div class='saldo-elegante'>$ ••••••••</div>",
                    unsafe_allow_html=True
                )

        with col_saldo2:

            st.write("")

            btn_label = (
                "👁️ Ocultar"
                if st.session_state.ver_saldo
                else "👁️ Ver Saldo"
            )

            if st.button(
                btn_label,
                use_container_width=True,
                key="ver_saldo_dashboard"
            ):
                st.session_state.ver_saldo = (
                    not st.session_state.ver_saldo
                )
                st.rerun()

    st.markdown(
        "<p style='font-weight:600; font-size:12px; "
        "text-transform:uppercase; letter-spacing:1px; "
        "margin-top:20px; margin-bottom:10px;'>"
        "📱 Menú de Navegación</p>",
        unsafe_allow_html=True
    )

    opciones_menu = [
        ("📊\nResumen", "Resumen"),
        ("💵\nOperaciones", "Operaciones"),
        (f"🗂️\nComprobantes\n({no_leidas})", "Comprobantes"),
        ("📈\nAnalítica Pro", "Analitica"),
        ("📜\nHistorial", "Historial"),
        ("⚙️\nConfiguración", "Configuracion")
    ]

    if es_admin:
        opciones_menu.append(
            ("👑\nAdministración", "Administracion")
        )

    for i in range(0, len(opciones_menu), 2):

        col_a, col_b = st.columns(2, gap="medium")

        with col_a:

            texto, destino = opciones_menu[i]

            if st.button(
                texto,
                use_container_width=True,
                key=f"menu_{destino}"
            ):
                st.session_state.seccion_cliente = destino
                st.rerun()

        if i + 1 < len(opciones_menu):

            with col_b:

                texto, destino = opciones_menu[i + 1]

                if st.button(
                    texto,
                    use_container_width=True,
                    key=f"menu_{destino}"
                ):
                    st.session_state.seccion_cliente = destino
                    st.rerun()

    st.divider()


    # =================================================
    # CONFIGURACIÓN
    # =================================================

    if st.session_state.seccion_cliente == "Configuracion":

        st.subheader("⚙️ Configuración de la cuenta")

        st.caption(
            "Administra tu contraseña y tus preguntas de seguridad."
        )

        with st.container(border=True):

            st.subheader("🔑 Cambiar contraseña")

            with st.form("cambiar_password_form"):

                password_actual = st.text_input(
                    "Contraseña actual",
                    type="password"
                )

                password_nueva = st.text_input(
                    "Nueva contraseña",
                    type="password",
                    help="Debe tener al menos 8 caracteres."
                )

                password_confirmacion = st.text_input(
                    "Confirmar nueva contraseña",
                    type="password"
                )

                cambiar_btn = st.form_submit_button(
                    "Actualizar contraseña",
                    use_container_width=True
                )

                if cambiar_btn:

                    if password_nueva != password_confirmacion:
                        st.error("Las nuevas contraseñas no coinciden.")

                    else:
                        exito, mensaje = cambiar_password(
                            usuario_actual,
                            password_actual,
                            password_nueva
                        )

                        if exito:
                            st.success(mensaje)
                        else:
                            st.error(mensaje)

        with st.container(border=True):

            st.subheader("🛡️ Preguntas de seguridad")

            tiene_preguntas = usuario_tiene_preguntas(
                usuario_actual
            )

            if tiene_preguntas:
                st.success(
                    "Ya tienes preguntas de seguridad configuradas. "
                    "Puedes actualizarlas desde aquí."
                )
            else:
                st.warning(
                    "Tu cuenta todavía no tiene preguntas de seguridad. "
                    "Añádelas ahora para poder recuperar tu contraseña en el futuro."
                )

            with st.form("configurar_seguridad_form"):

                password_confirmar_seguridad = st.text_input(
                    "Confirma tu contraseña actual",
                    type="password"
                )

                st.divider()

                pregunta_config1 = st.selectbox(
                    "Primera pregunta",
                    PREGUNTAS_SEGURIDAD,
                    key="pregunta_config1"
                )

                respuesta_config1 = st.text_input(
                    "Respuesta de la primera pregunta",
                    type="password"
                )

                pregunta_config2 = st.selectbox(
                    "Segunda pregunta",
                    PREGUNTAS_SEGURIDAD,
                    index=1,
                    key="pregunta_config2"
                )

                respuesta_config2 = st.text_input(
                    "Respuesta de la segunda pregunta",
                    type="password"
                )

                guardar_seguridad_btn = st.form_submit_button(
                    "Guardar preguntas de seguridad",
                    use_container_width=True
                )

                if guardar_seguridad_btn:

                    c = conn.cursor()

                    c.execute("""
                        SELECT password
                        FROM usuarios
                        WHERE username = ?
                    """, (usuario_actual,))

                    datos_password = c.fetchone()

                    if (
                        not datos_password
                        or not hmac.compare_digest(
                            datos_password[0],
                            hash_pass(password_confirmar_seguridad)
                        )
                    ):
                        st.error("La contraseña actual es incorrecta.")

                    elif pregunta_config1 == pregunta_config2:
                        st.error(
                            "Debes elegir dos preguntas diferentes."
                        )

                    elif (
                        not respuesta_config1.strip()
                        or not respuesta_config2.strip()
                    ):
                        st.error(
                            "Debes completar las dos respuestas."
                        )

                    else:
                        exito, mensaje = guardar_preguntas_seguridad(
                            usuario_actual,
                            pregunta_config1,
                            respuesta_config1,
                            pregunta_config2,
                            respuesta_config2
                        )

                        if exito:
                            st.success(mensaje)
                            st.rerun()
                        else:
                            st.error(mensaje)


    # =================================================
    # RESUMEN
    # =================================================

    elif st.session_state.seccion_cliente == "Resumen":

        with st.container(border=True):

            st.subheader("📊 Evolución General")

            if not df_hist.empty:

                fig = px.area(
                    df_hist,
                    x="fecha",
                    y="monto",
                    color="tipo",
                    title="Comportamiento del Capital",
                    markers=True
                )

            else:

                df_dummy = pd.DataFrame({
                    "Fecha": ["Inicio"],
                    "Capital": [saldo_cliente]
                })

                fig = px.line(
                    df_dummy,
                    x="Fecha",
                    y="Capital",
                    title="Estado Inicial de Cartera",
                    markers=True
                )

            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color=(
                    "#F8FAFC"
                    if st.session_state.modo_oscuro
                    else "#0F172A"
                ),
                height=300,
                margin=dict(l=10, r=10, t=40, b=10)
            )

            fig.update_xaxes(
                tickangle=0,
                automargin=True
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )


    # =================================================
    # ANALÍTICA
    # =================================================

    elif st.session_state.seccion_cliente == "Analitica":

        with st.container(border=True):

            st.subheader(
                "📈 Informe Analítico de Economista Senior"
            )

            st.markdown(
                "Análisis macrofinanciero automatizado del "
                "rendimiento de tus fondos basado en flujos "
                "de caja y liquidez actual:"
            )

            total_ingresos = (
                df_hist[df_hist["tipo"] == "Ingreso"]["monto"].sum()
                if not df_hist.empty else saldo_cliente
            )

            total_retiros = (
                df_hist[df_hist["tipo"] == "Retiro"]["monto"].sum()
                if not df_hist.empty else 0.0
            )

            ratio_liquidez = (
                saldo_cliente /
                (total_ingresos if total_ingresos > 0 else 1.0)
            ) * 100

            col_m1, col_m2, col_m3 = st.columns(3)

            col_m1.metric("Ingresos", f"${total_ingresos:,.2f}")
            col_m2.metric("Retiros", f"${total_retiros:,.2f}")
            col_m3.metric("Retención", f"{ratio_liquidez:.1f}%")

            st.info(
                f"**Diagnóstico Económico:**\n\n"
                f"- **Salud Financiera:** Retención de capital "
                f"del **{ratio_liquidez:.1f}%** sobre los flujos operados.\n"
                f"- **Proyección:** Tendencia alcista sostenida a 12 meses."
            )


    # =================================================
    # OPERACIONES
    # =================================================

    elif st.session_state.seccion_cliente == "Operaciones":

        with st.container(border=True):

            st.subheader("💵 Gestión de Ingresos y Retiros")

            opcion_op = st.radio(
                "Selecciona operación:",
                [
                    "📥 Depositar Dinero",
                    "📤 Retirar Dinero"
                ],
                horizontal=True
            )

            if opcion_op == "📥 Depositar Dinero":

                with st.form("form_ingreso_app"):

                    monto_ingreso = st.number_input(
                        "Monto a depositar ($)",
                        min_value=1.0,
                        step=10.0,
                        key="ing"
                    )

                    if st.form_submit_button(
                        "Confirmar Depósito",
                        use_container_width=True
                    ):

                        nuevo = registrar_transaccion(
                            usuario_actual,
                            "Ingreso",
                            monto_ingreso
                        )

                        st.success(
                            f"Depósito exitoso. Nuevo saldo: ${nuevo:,.2f}"
                        )

                        st.rerun()

            else:

                with st.form("form_retiro_app"):

                    monto_retiro = st.number_input(
                        "Monto a retirar ($)",
                        min_value=1.0,
                        step=10.0,
                        key="ret"
                    )

                    if st.form_submit_button(
                        "Confirmar Retiro",
                        use_container_width=True
                    ):

                        if monto_retiro <= saldo_cliente:

                            nuevo = registrar_transaccion(
                                usuario_actual,
                                "Retiro",
                                monto_retiro
                            )

                            st.success(
                                f"Retiro exitoso. Nuevo saldo: ${nuevo:,.2f}"
                            )

                            st.rerun()

                        else:
                            st.error("Fondos insuficientes.")


    # =================================================
    # HISTORIAL
    # =================================================

    elif st.session_state.seccion_cliente == "Historial":

        with st.container(border=True):

            st.subheader("📜 Registro Histórico de Movimientos")

            if not df_hist.empty:
                st.dataframe(
                    df_hist,
                    use_container_width=True
                )
            else:
                st.info("No hay transacciones registradas.")


    # =================================================
    # COMPROBANTES
    # =================================================

    elif st.session_state.seccion_cliente == "Comprobantes":

        with st.container(border=True):

            st.subheader("🗂️ Comprobantes y Resguardos de Pago")

            if not df_comps.empty:

                marcar_leidos(usuario_actual)

                for _, row in df_comps.iterrows():

                    st.markdown(
                        f"**📌 {row['titulo']}** — *{row['fecha']}*"
                    )

                    if (
                        pd.notna(row["imagen_path"])
                        and os.path.exists(row["imagen_path"])
                    ):

                        st.image(
                            row["imagen_path"],
                            caption=row["titulo"],
                            use_container_width=True
                        )

                    else:
                        st.warning(
                            "⚠️ La imagen no se encontró en el servidor local."
                        )

                    st.divider()

            else:
                st.info(
                    "No tienes comprobantes o imágenes guardadas "
                    "por la administración todavía."
                )


    # =================================================
    # ADMINISTRACIÓN
    # =================================================

    elif (
        st.session_state.seccion_cliente == "Administracion"
        and es_admin
    ):

        st.subheader("👑 Centro de Administración")

        st.caption(
            "Estas herramientas son exclusivas del administrador."
        )

        df_users = obtener_todos_usuarios()

        clientes_lista = df_users[
            df_users["rol"] == "cliente"
        ]["username"].tolist()

        # GESTIÓN DE CUENTAS

        with st.container(border=True):

            st.subheader("👥 Gestión de Usuarios")

            st.caption(
                "Administra el acceso y las cuentas de tus clientes."
            )

            if not df_users.empty:
                st.dataframe(
                    df_users,
                    use_container_width=True,
                    hide_index=True
                )

            total_clientes = len(clientes_lista)

            clientes_baneados = len(
                df_users[
                    (df_users["rol"] == "cliente")
                    & (df_users["estado"] == "BANEADO")
                ]
            )

            clientes_activos = total_clientes - clientes_baneados

            met1, met2, met3 = st.columns(3)

            met1.metric("Clientes", total_clientes)
            met2.metric("Activos", clientes_activos)
            met3.metric("Baneados", clientes_baneados)

            st.divider()

            if clientes_lista:

                cliente_gestion = st.selectbox(
                    "Selecciona el cliente que deseas gestionar",
                    clientes_lista,
                    key="cliente_gestion"
                )

                c = conn.cursor()

                c.execute("""
                    SELECT saldo, baneado
                    FROM usuarios
                    WHERE username = ?
                    AND rol = 'cliente'
                """, (cliente_gestion,))

                datos_cliente = c.fetchone()

                if datos_cliente:

                    saldo_gestion = float(datos_cliente[0])
                    esta_baneado = datos_cliente[1] == 1

                    st.write(f"**Usuario:** {cliente_gestion}")
                    st.write(f"**Saldo actual:** ${saldo_gestion:,.2f}")

                    if esta_baneado:
                        st.error("🚫 Esta cuenta está BANEADA.")
                    else:
                        st.success("🟢 Esta cuenta está ACTIVA.")

                    col_baneo, col_eliminar = st.columns(2)

                    with col_baneo:

                        if esta_baneado:

                            if st.button(
                                "🔓 Desbanear Usuario",
                                use_container_width=True,
                                key="desbanear_usuario"
                            ):

                                resultado = cambiar_estado_baneo(
                                    cliente_gestion,
                                    False
                                )

                                if resultado:
                                    st.success(
                                        f"{cliente_gestion} ha recuperado el acceso."
                                    )
                                    st.rerun()

                        else:

                            if st.button(
                                "🚫 Banear Usuario",
                                use_container_width=True,
                                key="banear_usuario"
                            ):

                                resultado = cambiar_estado_baneo(
                                    cliente_gestion,
                                    True
                                )

                                if resultado:
                                    st.success(
                                        f"{cliente_gestion} ha sido baneado."
                                    )
                                    st.rerun()

                    with col_eliminar:

                        st.write("")
                        st.caption("La eliminación es permanente.")

                    st.divider()

                    st.warning(
                        "⚠️ Eliminar una cuenta borra su saldo, movimientos "
                        "y comprobantes. Esta acción no se puede deshacer."
                    )

                    confirmar_eliminacion = st.checkbox(
                        f"Confirmo que deseo eliminar permanentemente "
                        f"la cuenta de {cliente_gestion}",
                        key="confirmar_eliminacion"
                    )

                    if st.button(
                        "🗑️ ELIMINAR CUENTA PERMANENTEMENTE",
                        type="primary",
                        disabled=not confirmar_eliminacion,
                        use_container_width=True,
                        key="eliminar_usuario"
                    ):

                        exito, mensaje = eliminar_usuario(
                            cliente_gestion
                        )

                        if exito:
                            st.success(mensaje)
                            st.rerun()
                        else:
                            st.error(mensaje)

            else:
                st.info("No hay clientes registrados.")

        # AJUSTAR SALDO Y ENVIAR COMPROBANTES

        col_admin_izq, col_admin_der = st.columns(2)

        with col_admin_izq:

            with st.container(border=True):

                st.subheader("💰 Ajustar Saldo")

                if clientes_lista:

                    with st.form("admin_saldo_form"):

                        cliente_elegido = st.selectbox(
                            "Cliente",
                            clientes_lista,
                            key="cliente_saldo"
                        )

                        monto_nuevo = st.number_input(
                            "Nuevo saldo ($)",
                            min_value=0.0,
                            step=50.0
                        )

                        if st.form_submit_button("Aplicar Ajuste"):

                            c = conn.cursor()

                            c.execute("""
                                SELECT baneado
                                FROM usuarios
                                WHERE username = ?
                            """, (cliente_elegido,))

                            estado = c.fetchone()

                            if estado and estado[0] == 0:

                                registrar_transaccion(
                                    cliente_elegido,
                                    "Ajuste Admin",
                                    monto_nuevo
                                )

                                st.success(
                                    f"Saldo de {cliente_elegido} actualizado."
                                )

                                st.rerun()

                            else:
                                st.error(
                                    "No puedes modificar una cuenta baneada."
                                )

                else:
                    st.info("No hay clientes registrados.")

        with col_admin_der:

            with st.container(border=True):

                st.subheader("📤 Enviar Comprobante")

                if clientes_lista:

                    with st.form("admin_comp_form"):

                        cli_comp = st.selectbox(
                            "Seleccionar cliente destinatario",
                            clientes_lista,
                            key="c_sel"
                        )

                        titulo_comp = st.text_input(
                            "Título del comprobante",
                            placeholder="Ej. Liquidación de retiro"
                        )

                        archivo_subido = st.file_uploader(
                            "Imagen o documento del comprobante",
                            type=["png", "jpg", "jpeg"]
                        )

                        if st.form_submit_button("Enviar Comprobante"):

                            if archivo_subido is not None:

                                extension = os.path.splitext(
                                    archivo_subido.name
                                )[1].lower()

                                nombre_seguro = (
                                    f"{uuid.uuid4().hex}{extension}"
                                )

                                ruta_archivo = os.path.join(
                                    CARPETA_COMPROBANTES,
                                    nombre_seguro
                                )

                                with open(ruta_archivo, "wb") as f:
                                    f.write(archivo_subido.getbuffer())

                                enviar_comprobante(
                                    cli_comp,
                                    titulo_comp,
                                    ruta_archivo
                                )

                                st.success(
                                    f"¡Comprobante enviado con éxito a {cli_comp}!"
                                )

                                st.rerun()

                            else:
                                st.error("Por favor, adjunta una imagen.")

                else:
                    st.info(
                        "Registra clientes primero para enviarles comprobantes."
                    )

        # TODOS LOS COMPROBANTES

        with st.container(border=True):

            st.subheader("📜 Todos los Comprobantes Emitidos")

            df_todos_comps = obtener_todos_los_comprobantes()

            if not df_todos_comps.empty:
                st.dataframe(
                    df_todos_comps,
                    use_container_width=True
                )
            else:
                st.info("Aún no se han emitido comprobantes.")
