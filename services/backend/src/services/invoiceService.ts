// src/services/invoiceService.ts
import db from '../db';
import { Invoice } from '../types/invoice';
import axios from 'axios';
import { promises as fs } from 'fs';
import * as path from 'path';

interface InvoiceRow {
  id: number; // cambio a number
  userId: number; // cambio a number
  amount: number;
  dueDate: Date;
  status: string;
}

//UTilizamos path.resolve para tener la ruta absoulta, para que no pueda salir del directorio
//actual
const INVOICES_DIRECTORY = path.resolve(__dirname, '..', '..', 'invoices_data'); 


// 1. Se define la "Lista Blanca" (Allowlist) de destinos permitidos.
// Solo se aceptarán estas marcas de tarjeta.
const PAYMENT_GATEWAY_URLS: { [key: string]: string } = {
  'visa': 'http://visa-payments.internal-api/pay',
  'master': 'http://mastercard.internal-api/charge',
  'amex': 'http://amex-gateway.internal-api/process'
};

class InvoiceService {
  static async list(userId: number, status?: string, operator?: string): Promise<Invoice[]> {
    const q = db<InvoiceRow>('invoices').where({ userId: userId });
//  if (status) q = q.andWhereRaw(" status "+ operator + " '"+ status +"'");                    // sql injection
    if (status && operator) {
      const allowedOperators = ['=', '!=', '>', '<', '>=', '<='];
      if (allowedOperators.includes(operator)) {
        q.andWhere('status', operator, status);
      } else {
        throw new Error('Operador no válido');
      }
    }
    
    const rows = await q.select();
    const invoices = rows.map(row => ({
      id: row.id,
      userId: row.userId,
      amount: row.amount,
      dueDate: row.dueDate,
      status: row.status
    } as Invoice));

    return invoices;
  }

  static async setPaymentCard(
    userId: number, // cambio a number
    invoiceId: number,  // cambio a number
    paymentBrand: string,
    ccNumber: string,
    ccv: string,
    expirationDate: string
  ) {

    // Se busca la URL en la lista segura usando la entrada del usuario como clave.
    const url = PAYMENT_GATEWAY_URLS[paymentBrand];

    // Se valida. Si 'paymentBrand' no estaba en la lista, la URL será 'undefined'
    //    y se rechazará la petición inmediatamente.
    if (!url) {
      throw new Error('Marca de tarjeta inválida');
    }

    // 4. Solo si la URL es válida y segura, se procede con la llamada de red.
    const paymentResponse = await axios.post(url, { // <-- SEGURO
      ccNumber,
      ccv,
      expirationDate
    });

    if (paymentResponse.status !== 200) {
      throw new Error('Payment failed');
    }

    // Update the invoice status in the database
    await db('invoices')
      .where({ id: invoiceId, userId })
      .update({ status: 'paid' });  
    };

  static async  getInvoice( invoiceId:number, userId: number): Promise<Invoice> {   // cambio a number
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId, userId: userId }).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    return invoice as Invoice;
  }


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
  };
};

export default InvoiceService;
