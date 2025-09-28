# Consigna Práctica 2 - Mitigación de Vulnerabilidades de CWE

**Aclaración**

Varias de estas vulnerabilidades se explotaron utilizando el user Test, que tiene el userId: 1

## 1 - Inyección SQL 

**Justificación**

En la función getReceipt que se encuentra en invoiceService, los parámetros status y operator se concatenan directamente en la consulta de SQL. Esto es una vulnerabilidad ya que un atacante puede inyectar código de SQL malicioso.

**Componente afectado:** `services/backend/src/services/invoiceService.ts`

**Parametro afectado:** let q

```typescript
class InvoiceService {
  static async list( userId: number, status?: string, operator?: string): Promise<Invoice[]> {
    let q = db<InvoiceRow>('invoices').where({ userId: userId });
    if (status) q = q.andWhereRaw(" status "+ operator + " '"+ status +"'");                    // sql injection
    const rows = await q.select();
    const invoices = rows.map(row => ({
      id: row.id,
      userId: row.userId,
      amount: row.amount,
      dueDate: row.dueDate,
      status: row.status} as Invoice
    ));
    return invoices;
  }
  ```

Esto es vulnerable ya que se utiliza directamente la concatenación de strings.

**PoC**

Siguiendo los siguientes pasos se puede reproducir la vulnerabilidad:

1- Entrar en la terminal de la computadora al servicio de backend
2- Ejecutar el siguiente comando: 
`curl -X GET 'http://localhost:5000/invoices?operator==&status=%27%20OR%201=1%20--' -H 'Authorization: Bearer <token generado anteriormente>'
`
- 3- Respuesta con JSON con datos de las facturas:
![sqlinjection](image.png)

**Fix**

## 2 - Hard Coded Credentials

**Justificación**

Se encuentra hardcodeado en el código el secreto que se utiliza para firmar los JWT. 
Esto es una vulnerabilidad ya que cualquiera que tenga acceso al código, sea externo o interno a la empresa, puede obtener ese secreto y generar tokens de acceso válidos para cualquier usuario y tomar el control de las cuentas

**PoC**

Siguiendo los siguientes pasos se puede reproducir la vulnerabilidad:

1. Entrar a la pagina http://jwtbuilder.jamiekurtz.com/ 

2. Ir a la parte de “Additional Claims” y borrar todo.
3. Agregar lo siguiente:
    Claim Type : id 
    Value: 1
4. Ir a la sección “Signed JSON Web Token” y en la parte de key poner el siguiente valor “secreto_super_seguro”
5. Darle al boton “Created Signed JWT” y copiar el token.
6. Ir al navegador 
7. Entrar a la url http://localhost:3000/login 
8. Entrar a las herramientas de desarrollo (F12)
9. Ir a la sección de storage
10. Seleccionar LocalStorage e ingresar al la url del localhost
11. Ver si existe algún valor, si existe modificar el token que se encuentra ahi por el token creado. De no existir, darle al más y agregar en Key el valor “token” y en Value poner el token.
12. Hacer refresh a la url y intentar entrar a http://localhost:3000/home 

**Fix**

## 3 - Server Side Request Fogery - SSRF

**Justificación**
En el invoiceService, la función setPaymentCard construye una URL usando el parámetro paymentBrand que le envía el usuario. Esto es una vulnerabilidad ya que un atacante puede usar esto para hacer que el servidor realice peticiones a otros servicios dentro de la red interna

**Componente Afectado:** `services/backend/src/services/invoiceService.ts`

**Parametro Afectado:** `const paymentResponse` 

```typescript
 const paymentResponse = await axios.post(`http://${paymentBrand}/payments`, {
      ccNumber,
      ccv,
      expirationDate
    });
    if (paymentResponse.status !== 200) {
      throw new Error('Payment failed');
    }
```

**PoC**
Siguiendo los siguientes pasos se puede reproducir la vulnerabilidad:

1. Abrir una terminal y ejecutar el siguiente comando. Esté comando lo que hace es poner a escuchar a nuestro servidor malicioso :`nc -lvp 9090`

2. Ir a la terminal donde tenemos abierto el proyecto de backend y ejecutar:
`curl -X POST http://localhost:5000/invoices/1/pay
 -H "Authorization: Bearer <token generado anteriormente>"
-H "Content-Type: application/json" 
-d '{
  "paymentBrand": "127.0.0.1:9090",
  "ccNumber": "4111222233334444",
  "ccv": "123",
  "expirationDate": "12/29"
}'`
3. Volver a la terminal que estaba escuchando y se puede observar que escucho el post que realizamos

![SSRF](image-1.png)

**Fix**

## 4 - Path Traversal

**Justificación**
La funcionalidad para descargar archivos no valida correctamente la ruta del archivo, lo que hace que esté permitido el uso de caracteres como ../. Esto es una vulnerabilidad ya que el atacante puede navegar por distintas partes del directorio y puede llegar a leer archivos de configuración sensibles o archivos del sistema operativo.

**Componentes afectados:** 
`src/controllers/invoiceController.ts → getInvoicePDF`

`src/services/invoiceService.ts → InvoiceService.getReceipt`

**Endpoint vulnerable:**
`GET /invoices/:id/invoice`

**Parametro vulnerable:** `pdfName`

```typescript
static async getReceipt(
    invoiceId: string,
    pdfName: string
  ) {
    // check if the invoice exists
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId }).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    try {
      const filePath = `/invoices/${pdfName}`;
      const content = await fs.readFile(filePath, 'utf-8');
      return content;
    } catch (error) {
      // send the error to the standard output
      console.error('Error reading receipt file:', error);
      throw new Error('Receipt not found');

    } 
```

**PoC**
Siguiendo los siguientes pasos se puede reproducir la vulnerabilidad:

1. En Postman hacer el siguiente request:
`GET 'http://localhost:5000/invoices/1/invoice?pdfName=../../../../../../../../../../etc/passwd`
2. Muestra nombres de usuarios e IDs válidos además de estructura del sistema con los directrorios home y shells de acceso /bin/bash


**Fix**
Para arrelgar la vulnerabilidad, utilizamos la estrategía es la de validación de ruta canónica.

Pusimos una variable llamada `INVOICE_DIRECTORY` para asegurarnos de que la ruta solicitada nunca salga del directorio base usando path.resolve(). 

```typescript
const INVOICES_DIRECTORY = path.resolve(__dirname, '..', '..', 'invoices_data');
```
En la función `getReceipt` se usa path.join para construir la ruta de fomra segura como lo dimos en clase, normalizando automaticamente la ruta y eliminando secuencias ../ que intenten escapar del directorio actual. 

En la variable 
```typescript
const requestFilePath = path.join(INVOICES_DIRECTORY, pdfName);
```
 Se verifica usando startsWith() que la ruta de requestFilePath, siempre coincida con el directorio actual, de los contrario se rechaza la solicitud. 



```typescript
static async getReceipt(
    invoiceId: number,   // cambio a number
    pdfName: string,
    userId: number
  ) {
    // check if the invoice exists
    const invoice = await db<InvoiceRow>('invoices').where({id: invoiceId, userId: userId}).first();
    if (!invoice) {
      throw new Error('Factura no encontrada o usuario  no autorizado'); //Aviso de error
    }

    const requestFilePath = path.join(INVOICES_DIRECTORY, pdfName)

    if (!requestFilePath.startsWith(INVOICES_DIRECTORY)) {
      throw new Error('Error, no puede acceder fuera del directorio predeterminado'); // Aviso de error
    }

    try {
      const content = await fs.readFile(requestFilePath, 'utf-8');  //fix para la vulnerabilidad
      return content;
    } catch (error) {
      // send the error to the standard output
      console.error('Error reading receipt file:', error);
      throw new Error('Receipt not found');
    } 
```
