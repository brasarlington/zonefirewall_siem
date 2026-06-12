use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

// Definimos la estructura exacta que esperamos leer de nuestro config/zones_config.json
#[derive(Deserialize, Debug)]
struct FirewallConfig {
    zones: HashMap<String, Vec<String>>,
    blocked_ports: Vec<u16>,
}

fn main() {
    // 1. CONTROL DE PRIVILEGIOS
    // Modificar tablas de Netfilter en Linux requiere privilegios de superusuario.
    // Usamos la función getuid de la librería estándar de C (libc) para verificarlo de forma segura.
    if unsafe { libc::getuid() } != 0 {
        eprintln!("[-] Error Crítico: Este software requiere privilegios de root. Ejecútalo con 'sudo'.");
        std::process::exit(1);
    }

    // 2. LECTURA Y DESERIALIZACIÓN DE LA CONFIGURACIÓN (JSON -> ESTRUCTURA DE RUST)
    let config_path = "config/zones_config.json";
    let mut file = File::open(config_path)
        .expect("[-] No se pudo abrir config/zones_config.json. Verifica que el archivo exista.");
    
    let mut json_contents = String::new();
    file.read_to_string(&mut json_contents).unwrap();
    
    let config: FirewallConfig = serde_json::from_str(&json_contents)
        .expect("[-] Error: El formato del archivo JSON de configuración es inválido.");

    // 3. GENERACIÓN DINÁMICA DEL RULESET PARA NFTABLES
    // Usamos tablas 'inet' para dar soporte nativo y simultáneo a IPv4 e IPv6.
    let mut nft_ruleset = String::from("#!/usr/sbin/nft -f\nflush ruleset\n\ntable inet zbf_infra {\n");

    // Construcción dinámica de los "Sets" (Zonas de Red)
    for (zone_name, interfaces) in &config.zones {
        let ifaces_str = interfaces.iter()
            .map(|i| format!("\"{}\"", i))
            .collect::<Vec<String>>()
            .join(", ");
        nft_ruleset.push_str(&format!(
            "    set z_{} {{ type ifname; elements = {{ {} }} }}\n", 
            zone_name.to_lowercase(), 
            ifaces_str
        ));
    }

    // Inicialización de la cadena Forward (Tráfico entre zonas) con política por defecto 'drop' (Seguridad Zero-Trust)
    nft_ruleset.push_str("\n    chain forward {\n        type filter hook forward priority filter; policy drop;\n        \n        # Inspección de Estado (Stateful): Permitir paquetes de conexiones ya establecidas\n        ct state established,related accept\n");

    // Inyección de los puertos bloqueados si el array en el JSON contiene elementos
    if !config.blocked_ports.is_empty() {
        let ports_str = config.blocked_ports.iter()
            .map(|p| p.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        
        // Redirigimos el log al Grupo 1 (NFLOG) con un prefijo identificador para que Promtail/Loki lo rastreen fácilmente
        nft_ruleset.push_str(&format!(
            "\n        # Reglas de bloqueo perimetral generadas por el binario de Rust\n\
                     iifname @z_wan tcp dport {{ {} }} log group 1 prefix \"RUST-ZBF-BLOCK\" drop\n", 
            ports_str
        ));
    }

    // Regla de cierre para capturar y registrar cualquier otro tráfico que intente violar las políticas de las zonas
    nft_ruleset.push_str("\n        # Registro y descarte implícito por defecto de zonas\n        log group 1 prefix \"RUST-ZBF-DEFAULT-DROP\" drop\n    }\n}\n");

    // 4. TRANSACCIÓN ATÓMICA AL KERNEL DE LINUX
    // Invocamos la CLI de nftables pasándole las reglas directamente por la Entrada Estándar (STDIN)
    // Esto es mucho más rápido y seguro que escribir archivos temporales en el disco duro.
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("[-] Falló la comunicación con el subsistema nftables.");

    {
        let stdin = child.stdin.as_mut().expect("[-] No se pudo abrir el canal STDIN hacia nftables.");
        stdin.write_all(nft_ruleset.as_bytes()).expect("[-] Error al transmitir el flujo de bytes al Kernel.");
    }

    let output = child.wait_with_output().unwrap();

    // 5. EVALUACIÓN DEL RESULTADO DE LA TRANSACCIÓN
    if output.status.success() {
        println!("[+] Éxito: El motor en Rust ha compilado y aplicado las políticas de zona en Netfilter de forma atómica.");
    } else {
        let error_log = String::from_utf8_lossy(&output.stderr);
        eprintln!("[-] Error Crítico al compilar las reglas de nftables:\n{}", error_log);
    }
}