// Configuración del despliegue. No hay secretos aquí y no puede haberlos: esto
// es una web estática servida desde GitHub Pages, así que cualquier cosa que
// pusiera se leería con ver el fuente.
//
// El client id de OAuth no es un secreto —Google lo trata como público en los
// clientes de navegador—, pero sí es propio de cada despliegue: quien levante
// su copia tiene que crear el suyo en la consola de Google Cloud, con el scope
// `drive.appdata` y el origen de su sitio autorizado. Vacío = sin sincronizar,
// que es un modo perfectamente utilizable: el vault sigue funcionando entero
// contra el almacenamiento del navegador.
export const GOOGLE_CLIENT_ID = '';
