package iessanalbertomagno.org;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Pattern;

/**
 * Punto de entrada de la aplicación.
 *
 * Audita un lote de passwords candidatos lanzando, por cada uno, tres
 * comprobaciones en paralelo sobre un pool de hilos fijo:
 *   - Longitud:    la longitud está entre los límites prefijados.
 *   - Complejidad: tiene mayúscula, minúscula, dígito y carácter especial.
 *   - FiloPrimo:   la suma de los códigos ASCII del password es un número primo.
 *
 * Después imprime, por cada password, el resultado de las tres comprobaciones.
 */
public class ComprobadorPasswords {


    /*CONSTANTES*/

    //Numero de hilos no se especifica pongo 3
     public static final int NUMERO_HILOS = 3;

    // Límites de Longitud.
    public static final int LONGITUD_MINIMA = 8;
    public static final int LONGITUD_MAXIMA = 20;

    // Número de tareas que se crean por cada password (Longitud, Complejidad y FiloPrimo).
    public static final int COMPROBACIONES = 3;

    // Caracteres especiales válidos: @ # $ % & * ! + -
    public static final Pattern PATRON_ESPECIALES = Pattern.compile("[@#$%&*!+-]");

    // Textos de la salida, definidos una vez para no repetir literales.
    public static final String CUMPLE = "OK";
    public static final String NO_CUMPLE = "NO";

    // Lote de passwords candidatos que se van a auditar.

    public static final String[] PASSWORDS = {
            "jhkjhddS·$_", "akasddfoadfj232", "IAJSDQW", "LSADUANDLIAUhkjh(/&", "saBIÑaNIGO26", "jUaN2334++ASDA",
            "jhkDSSjhddS·$_", "akaeee*f56757oadfj232", "IAJSDQW", "LSADUAND77LIAUhkjh(/&", "saBIÑaNIGO26", "jUaN2334++ASDA",
            "jhkjhWQEddS·$_", "akasddfoadfj232", "IAJSDQW", "LSADUANDLIAUhkjh(/&", "saBIÑaNIGO26++", "jUaN2334++ASDA",
            "jhkddS·$_", "akasddKKKfj232", "kkkk", "1234", "pasword", "Jaca",
    };// PASSWORDS

    public static void main(String[] args) throws InterruptedException, ExecutionException {

        // PREPARACIÓN DE TAREAS
        // Una única lista con las tres tareas de cada password, siempre en el  mismo orden:
        // Longitud, Complejidad, FiloPrimo, para localizar después el resultado de cada tarea por posición.

        List<Callable<Boolean>> l_Tareas = new ArrayList<>(PASSWORDS.length * COMPROBACIONES);
        for (String l_Password : PASSWORDS) {
            l_Tareas.add(new Longitud(l_Password));
            l_Tareas.add(new Complejidad(l_Password));
            l_Tareas.add(new FiloPrimo(l_Password));
        }

        // EJECUCIÓN EN PARALELO
        // Pool de tamaño fijo: 3
        ExecutorService l_Executor = Executors.newFixedThreadPool(NUMERO_HILOS);

        // UN solo invokeAll con todas las tareas. Bloquea hasta que terminan todas y devuelve los Future
        // en el mismo orden que la lista de tareas.
        List<Future<Boolean>> l_Resultados = l_Executor.invokeAll(l_Tareas);

        // Ya no entran más tareas; los hilos del pool terminan y se liberan.
        l_Executor.shutdown();

        // PRESENTACIÓN DE RESULTADOS
        // el texto se acumula en un StringBuilder y se imprime de una vez.
        StringBuilder l_Salida = new StringBuilder();

        // Posición dentro de la lista de resultados. Se avanza de 3 en 3 porque cada password origina tres tareas:
        // Longitud, Complejidad y FiloPrimo y uso de invokeAll para garantizar que están acabadas.
        int l_Posicion = 0;
        for (String l_Password : PASSWORDS) {
            l_Salida.append("Password: ").append(l_Password )
                    .append("\n Longitud: ").append(l_Resultados.get(l_Posicion++).get() ? CUMPLE : NO_CUMPLE)
                    .append(" | Complejidad: ").append(l_Resultados.get(l_Posicion++).get() ? CUMPLE : NO_CUMPLE)
                    .append(" | FiloPrimo: ").append(l_Resultados.get(l_Posicion++).get() ? CUMPLE : NO_CUMPLE)
                    .append("\n---------------------------------------------------\n");
        }
        System.out.print(l_Salida);
    }
}

/** LONGITUD MÁXIMA Y MÍNIMA
 * Comprueba si la longitud del password está dentro de los límites (LONGITUD_MINIMA y LONGITUD_MAXIMA incluidos).
 */
class Longitud implements Callable<Boolean> {

    // Password a analizar (inmutable: la tarea solo lo lee).
    private final String a_Password;

    public Longitud(String p_Password) {
        a_Password = p_Password;
    }

    @Override
    public Boolean call() {
        int l_Longitud = a_Password.length();
        // Se devuelve directamente la condición, sin if/else intermedio.
        return (l_Longitud >= ComprobadorPasswords.LONGITUD_MINIMA)
                && (l_Longitud <= ComprobadorPasswords.LONGITUD_MAXIMA);
    }
}

/** COMPLEJIDAD
 * Comprueba la complejidad del password: al menos una mayúscula, una minúscula, un dígito y un carácter
 * especial de @ # $ % & * ! + -
 */
class Complejidad implements Callable<Boolean> {

    // Password a analizar (inmutable: la tarea solo lo lee).
    private final String a_Password;

    public Complejidad(String p_Password) {
        a_Password = p_Password;
    }

    @Override
    public Boolean call() {
        boolean l_TieneMayuscula = false;
        boolean l_TieneMinuscula = false;
        boolean l_TieneDigito = false;
        int l_Indice = 0;

        // Recorremos el password y se detiene cuando ya se han visto las tres clases de caracteres.
        // uso charAt para evitar crear una copia del texto como haría toCharArray().
        while ((l_Indice < a_Password.length()) && !(l_TieneMayuscula && l_TieneMinuscula && l_TieneDigito)) {
            char l_Candidato = a_Password.charAt(l_Indice++);
            l_TieneMayuscula |= Character.isUpperCase(l_Candidato);
            l_TieneMinuscula |= Character.isLowerCase(l_Candidato);
            l_TieneDigito |= Character.isDigit(l_Candidato);
        }

        // Uso && para evaluar de izquierda a derecha y corta en cuanto algo falla.
        return l_TieneMayuscula && l_TieneMinuscula && l_TieneDigito
                && ComprobadorPasswords.PATRON_ESPECIALES.matcher(a_Password).find();
    }
}

/** FILOPRIMO
 * Comprueba si la suma de los códigos ASCII de los caracteres del password es un número primo.
 */
class FiloPrimo implements Callable<Boolean> {

    // Password a analizar (inmutable: la tarea solo lo lee).
    private final String a_Password;

    public FiloPrimo(String p_Password) {
        a_Password = p_Password;
    }

    @Override
    public Boolean call() {
        //Sumar el código ASCII de cada carácter.
        int l_Suma = 0;
        for (int l_Indice = 0; l_Indice < a_Password.length(); l_Indice++) {
            char l_Candidato = a_Password.charAt(l_Indice);
            l_Suma += (int) l_Candidato;
        }

        // Comprobar si la suma es prima probando divisores desde 2 hasta su raíz cuadrada
        int l_Divisor = 2;
        boolean l_EsPrimo = l_Suma > 1;

        // Se para en cuanto aparece un divisor exacto y avanza al siguiente candidato.
        while ((l_Divisor <= (l_Suma / l_Divisor)) && l_EsPrimo)
            l_EsPrimo = ((l_Suma % l_Divisor++) != 0);

        return l_EsPrimo;
    }
}