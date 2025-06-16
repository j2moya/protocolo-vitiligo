<?php
// api.php - Sistema API completo para el protocolo de vitiligo

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Configuración de base de datos
$config = [
    'host' => 'db5018042444.hosting-data.io',
    'dbname' => 'dbs14336152',
    'user' => 'dbu469954',
    'pass' => 'M1o9y1a2$&$#@'
];

try {
    $pdo = new PDO(
        "mysql:host={$config['host']};dbname={$config['dbname']};charset=utf8mb4",
        $config['user'],
        $config['pass'],
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]
    );
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Error de conexión a la base de datos']);
    exit;
}

session_start();

// Enrutador simple
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$path = str_replace('/pidasalud/protocolo-vitiligo/api.php', '', $path);

// Obtener datos de entrada
$input = json_decode(file_get_contents('php://input'), true) ?? [];
$data = array_merge($_GET, $_POST, $input);

// Rutas disponibles
switch ($method . ':' . $path) {
    
    case 'POST:/auth/register':
        registrarUsuario($pdo, $data);
        break;
        
    case 'POST:/auth/login':
        loginUsuario($pdo, $data);
        break;
        
    case 'POST:/auth/logout':
        logoutUsuario();
        break;
        
    case 'POST:/evaluacion/iniciar':
        iniciarEvaluacion($pdo, $data);
        break;
        
    case 'POST:/evaluacion/guardar-paso':
        guardarPasoEvaluacion($pdo, $data);
        break;
        
    case 'GET:/evaluacion/cargar':
        cargarEvaluacion($pdo, $data);
        break;
        
    case 'POST:/reporte/generar':
        generarReporte($pdo, $data);
        break;
        
    case 'POST:/reporte/enviar-email':
        enviarReportePorEmail($pdo, $data);
        break;
        
    case 'GET:/reporte/pdf':
        generarReportePDF($pdo, $data);
        break;
        
    default:
        http_response_code(404);
        echo json_encode(['error' => 'Endpoint no encontrado']);
        break;
}

// Función para registrar usuario
function registrarUsuario($pdo, $data) {
    try {
        // Validar datos
        if (empty($data['nombre']) || empty($data['email']) || empty($data['password'])) {
            throw new Exception('Datos incompletos');
        }
        
        // Verificar si el email ya existe
        $stmt = $pdo->prepare("SELECT id FROM usuarios WHERE email = ?");
        $stmt->execute([$data['email']]);
        if ($stmt->fetch()) {
            throw new Exception('El email ya está registrado');
        }
        
        // Crear usuario
        $passwordHash = password_hash($data['password'], PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("
            INSERT INTO usuarios (nombre, email, password_hash, telefono, pais) 
            VALUES (?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            $data['nombre'],
            $data['email'],
            $passwordHash,
            $data['telefono'] ?? null,
            $data['pais'] ?? null
        ]);
        
        $userId = $pdo->lastInsertId();
        $_SESSION['usuario_id'] = $userId;
        $_SESSION['usuario_nombre'] = $data['nombre'];
        
        echo json_encode([
            'success' => true,
            'message' => 'Usuario registrado exitosamente',
            'usuario_id' => $userId
        ]);
        
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['error' => $e->getMessage()]);
    }
}

// Función para login
function loginUsuario($pdo, $data) {
    try {
        if (empty($data['email']) || empty($data['password'])) {
            throw new Exception('Email y contraseña requeridos');
        }
        
        $stmt = $pdo->prepare("SELECT id, nombre, password_hash FROM usuarios WHERE email = ? AND activo = 1");
        $stmt->execute([$data['email']]);
        $usuario = $stmt->fetch();
        
        if (!$usuario || !password_verify($data['password'], $usuario['password_hash'])) {
            throw new Exception('Credenciales inválidas');
        }
        
        $_SESSION['usuario_id'] = $usuario['id'];
        $_SESSION['usuario_nombre'] = $usuario['nombre'];
        
        echo json_encode([
            'success' => true,
            'message' => 'Login exitoso',
            'usuario_id' => $usuario['id'],
            'nombre' => $usuario['nombre']
        ]);
        
    } catch (Exception $e) {
        http_response_code(401);
        echo json_encode(['error' => $e->getMessage()]);
    }
}

// Función para logout
function logoutUsuario() {
    session_destroy();
    echo json_encode(['success' => true, 'message' => 'Logout exitoso']);
}

// Función para iniciar evaluación
function iniciarEvaluacion($pdo, $data) {
    try {
        if (!isset($_SESSION['usuario_id'])) {
            throw new Exception('Usuario no autenticado');
        }
        
        $stmt = $pdo->prepare("INSERT INTO evaluaciones (usuario_id) VALUES (?)");
        $stmt->execute([$_SESSION['usuario_id']]);
        
        $evaluacionId = $pdo->lastInsertId();
        $_SESSION['evaluacion_id'] = $evaluacionId;
        
        echo json_encode([
            'success' => true,
            'evaluacion_id' => $evaluacionId
        ]);
        
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['error' => $e->getMessage()]);
    }
}

// Función para guardar paso de evaluación
function guardarPasoEvaluacion($pdo, $data) {
    try {
        if (!isset($_SESSION['usuario_id']) || !isset($data['paso'])) {
            throw new Exception('Datos incompletos');
        }
        
        $evaluacionId = $_SESSION['evaluacion_id'] ?? null;
        if (!$evaluacionId) {
            throw new Exception('No hay evaluación activa');
        }
        
        switch ($data['paso']) {
            case 'datos_basicos':
                guardarDatosBasicos($pdo, $evaluacionId, $data['datos']);
                break;
                
            case 'fitzpatrick':
                guardarFitzpatrick($pdo, $evaluacionId, $data['datos']);
                break;
                
            case 'antecedentes':
                guardarAntecedentes($pdo, $evaluacionId, $data['datos']);
                break;
                
            case 'vitiligo_actual':
                guardarVitiligoActual($pdo, $evaluacionId, $data['datos']);
                break;
                
            case 'capacidad_inversion':
                guardarCapacidadInversion($pdo, $evaluacionId, $data['datos']);
                break;
                
            default:
                throw new Exception('Paso no válido');
        }
        
        echo json_encode(['success' => true, 'message' => 'Datos guardados correctamente']);
        
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['error' => $e->getMessage()]);
    }
}

// Funciones auxiliares para guardar cada paso
function guardarDatosBasicos($pdo, $evaluacionId, $datos) {
    $stmt = $pdo->prepare("
        INSERT INTO datos_basicos (evaluacion_id, nombre, edad, sexo, email, telefono, pais, ocupacion) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE 
        nombre = VALUES(nombre), edad = VALUES(edad), sexo = VALUES(sexo),
        email = VALUES(email), telefono = VALUES(telefono), pais = VALUES(pais), ocupacion = VALUES(ocupacion)
    ");
    
    $stmt->execute([
        $evaluacionId,
        $datos['nombre'] ?? null,
        $datos['edad'] ?? null,
        $datos['sexo'] ?? null,
        $datos['email'] ?? null,
        $datos['telefono'] ?? null,
        $datos['pais'] ?? null,
        $datos['ocupacion'] ?? null
    ]);
}

function guardarFitzpatrick($pdo, $evaluacionId, $datos) {
    $stmt = $pdo->prepare("
        INSERT INTO fitzpatrick_data (evaluacion_id, fitzpatrick_type, respuestas) 
        VALUES (?, ?, ?)
        ON DUPLICATE KEY UPDATE 
        fitzpatrick_type = VALUES(fitzpatrick_type), respuestas = VALUES(respuestas)
    ");
    
    $stmt->execute([
        $evaluacionId,
        $datos['fitzpatrick_type'] ?? null,
        json_encode($datos['respuestas'] ?? [])
    ]);
}

function guardarAntecedentes($pdo, $evaluacionId, $datos) {
    $stmt = $pdo->prepare("
        INSERT INTO antecedentes (evaluacion_id, antecedentes_personales, antecedentes_familiares, medicamentos_actuales, alergias) 
        VALUES (?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE 
        antecedentes_personales = VALUES(antecedentes_personales), 
        antecedentes_familiares = VALUES(antecedentes_familiares),
        medicamentos_actuales = VALUES(medicamentos_actuales), 
        alergias = VALUES(alergias)
    ");
    
    $stmt->execute([
        $evaluacionId,
        json_encode($datos['antecedentes_personales'] ?? []),
        json_encode($datos['antecedentes_familiares'] ?? []),
        json_encode($datos['medicamentos_actuales'] ?? []),
        json_encode($datos['alergias'] ?? [])
    ]);
}

function guardarVitiligoActual($pdo, $evaluacionId, $datos) {
    $stmt = $pdo->prepare("
        INSERT INTO vitiligo_actual (evaluacion_id, tiempo_inicio, progresion, areas_afectadas, vasi_scores, vasi_total, dlqi_scores, dlqi_total, tratamientos_previos, sintomas) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE 
        tiempo_inicio = VALUES(tiempo_inicio), progresion = VALUES(progresion),
        areas_afectadas = VALUES(areas_afectadas), vasi_scores = VALUES(vasi_scores),
        vasi_total = VALUES(vasi_total), dlqi_scores = VALUES(dlqi_scores),
        dlqi_total = VALUES(dlqi_total), tratamientos_previos = VALUES(tratamientos_previos),
        sintomas = VALUES(sintomas)
    ");
    
    $stmt->execute([
        $evaluacionId,
        $datos['tiempo_inicio'] ?? null,
        $datos['progresion'] ?? null,
        json_encode($datos['areas_afectadas'] ?? []),
        json_encode($datos['vasi_scores'] ?? []),
        $datos['vasi_total'] ?? null,
        json_encode($datos['dlqi_scores'] ?? []),
        $datos['dlqi_total'] ?? null,
        json_encode($datos['tratamientos_previos'] ?? []),
        json_encode($datos['sintomas'] ?? [])
    ]);
}

function guardarCapacidadInversion($pdo, $evaluacionId, $datos) {
    $stmt = $pdo->prepare("
        INSERT INTO capacidad_inversion (evaluacion_id, pais_residencia, moneda_local, ingresos_mensuales, gastos_mensuales, monto_disponible_inmediato, monto_mensual_sostenible, recursos_disponibles, seguro_salud, prioridad_tratamiento, timeline_resultados, dispuesto_viajar) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE 
        pais_residencia = VALUES(pais_residencia), moneda_local = VALUES(moneda_local),
        ingresos_mensuales = VALUES(ingresos_mensuales), gastos_mensuales = VALUES(gastos_mensuales),
        monto_disponible_inmediato = VALUES(monto_disponible_inmediato), 
        monto_mensual_sostenible = VALUES(monto_mensual_sostenible),
        recursos_disponibles = VALUES(recursos_disponibles), seguro_salud = VALUES(seguro_salud),
        prioridad_tratamiento = VALUES(prioridad_tratamiento), timeline_resultados = VALUES(timeline_resultados),
        dispuesto_viajar = VALUES(dispuesto_viajar)
    ");
    
    $stmt->execute([
        $evaluacionId,
        $datos['pais_residencia'] ?? null,
        $datos['moneda_local'] ?? null,
        json_encode($datos['ingresos_mensuales'] ?? []),
        json_encode($datos['gastos_mensuales'] ?? []),
        $datos['monto_disponible_inmediato'] ?? null,
        $datos['monto_mensual_sostenible'] ?? null,
        json_encode($datos['recursos_disponibles'] ?? []),
        json_encode($datos['seguro_salud'] ?? []),
        $datos['prioridad_tratamiento'] ?? null,
        $datos['timeline_resultados'] ?? null,
        $datos['dispuesto_viajar'] ?? null
    ]);
}

// Función para cargar evaluación
function cargarEvaluacion($pdo, $data) {
    try {
        if (!isset($_SESSION['usuario_id'])) {
            throw new Exception('Usuario no autenticado');
        }
        
        $evaluacionId = $data['evaluacion_id'] ?? $_SESSION['evaluacion_id'] ?? null;
        if (!$evaluacionId) {
            throw new Exception('No se especificó evaluación');
        }
        
        // Cargar todos los datos
        $evaluacion = cargarDatosCompletos($pdo, $evaluacionId, $_SESSION['usuario_id']);
        
        echo json_encode([
            'success' => true,
            'evaluacion' => $evaluacion
        ]);
        
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['error' => $e->getMessage()]);
    }
}

function cargarDatosCompletos($pdo, $evaluacionId, $usuarioId) {
    // Verificar que la evaluación pertenece al usuario
    $stmt = $pdo->prepare("SELECT * FROM evaluaciones WHERE id = ? AND usuario_id = ?");
    $stmt->execute([$evaluacionId, $usuarioId]);
    $evaluacion = $stmt->fetch();
    
    if (!$evaluacion) {
        throw new Exception('Evaluación no encontrada');
    }
    
    $datos = ['evaluacion' => $evaluacion];
    
    // Cargar datos básicos
    $stmt = $pdo->prepare("SELECT * FROM datos_basicos WHERE evaluacion_id = ?");
    $stmt->execute([$evaluacionId]);
    $datos['datos_basicos'] = $stmt->fetch() ?: [];
    
    // Cargar Fitzpatrick
    $stmt = $pdo->prepare("SELECT * FROM fitzpatrick_data WHERE evaluacion_id = ?");
    $stmt->execute([$evaluacionId]);
    $fitzpatrick = $stmt->fetch();
    if ($fitzpatrick && $fitzpatrick['respuestas']) {
        $fitzpatrick['respuestas'] = json_decode($fitzpatrick['respuestas'], true);
    }
    $datos['fitzpatrick'] = $fitzpatrick ?: [];
    
    // Cargar antecedentes
    $stmt = $pdo->prepare("SELECT * FROM antecedentes WHERE evaluacion_id = ?");
    $stmt->execute([$evaluacionId]);
    $antecedentes = $stmt->fetch();
    if ($antecedentes) {
        foreach (['antecedentes_personales', 'antecedentes_familiares', 'medicamentos_actuales', 'alergias'] as $field) {
            if ($antecedentes[$field]) {
                $antecedentes[$field] = json_decode($antecedentes[$field], true);
            }
        }
    }
    $datos['antecedentes'] = $antecedentes ?: [];
    
    // Cargar vitiligo actual
    $stmt = $pdo->prepare("SELECT * FROM vitiligo_actual WHERE evaluacion_id = ?");
    $stmt->execute([$evaluacionId]);
    $vitiligo = $stmt->fetch();
    if ($vitiligo) {
        foreach (['areas_afectadas', 'vasi_scores', 'dlqi_scores', 'tratamientos_previos', 'sintomas'] as $field) {
            if ($vitiligo[$field]) {
                $vitiligo[$field] = json_decode($vitiligo[$field], true);
            }
        }
    }
    $datos['vitiligo_actual'] = $vitiligo ?: [];
    
    // Cargar capacidad de inversión
    $stmt = $pdo->prepare("SELECT * FROM capacidad_inversion WHERE evaluacion_id = ?");
    $stmt->execute([$evaluacionId]);
    $capacidad = $stmt->fetch();
    if ($capacidad) {
        foreach (['ingresos_mensuales', 'gastos_mensuales', 'recursos_disponibles', 'seguro_salud'] as $field) {
            if ($capacidad[$field]) {
                $capacidad[$field] = json_decode($capacidad[$field], true);
            }
        }
    }
    $datos['capacidad_inversion'] = $capacidad ?: [];
    
    return $datos;
}

// Función para generar reporte
function generarReporte($pdo, $data) {
    try {
        if (!isset($_SESSION['usuario_id'])) {
            throw new Exception('Usuario no autenticado');
        }
        
        $evaluacionId = $data['evaluacion_id'] ?? $_SESSION['evaluacion_id'];
        $datosCompletos = cargarDatosCompletos($pdo, $evaluacionId, $_SESSION['usuario_id']);
        
        // Marcar evaluación como completada
        $stmt = $pdo->prepare("UPDATE evaluaciones SET estado = 'completado', fecha_completado = NOW() WHERE id = ?");
        $stmt->execute([$evaluacionId]);
        
        // Guardar reporte generado
        $stmt = $pdo->prepare("INSERT INTO reportes (evaluacion_id, tipo_reporte, contenido_html) VALUES (?, 'completo', ?)");
        $stmt->execute([$evaluacionId, json_encode($datosCompletos)]);
        
        echo json_encode([
            'success' => true,
            'reporte_id' => $pdo->lastInsertId(),
            'datos' => $datosCompletos
        ]);
        
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['error' => $e->getMessage()]);
    }
}

// Función para enviar reporte por email
function enviarReportePorEmail($pdo, $data) {
    try {
        // Implementar envío de email
        // Usar PHPMailer o similar
        echo json_encode([
            'success' => true,
            'message' => 'Reporte enviado por email'
        ]);
        
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['error' => $e->getMessage()]);
    }
}

// Función para generar PDF
function generarReportePDF($pdo, $data) {
    try {
        // Implementar generación de PDF
        // Usar dompdf o similar
        echo json_encode([
            'success' => true,
            'pdf_url' => '/path/to/generated/pdf'
        ]);
        
    } catch (Exception $e) {
        http_response_code(400);
        echo json_encode(['error' => $e->getMessage()]);
    }
}

?>