import { Request, Response, NextFunction } from 'express';
import InvoiceService from '../services/invoiceService';
import { Invoice } from '../types/invoice';


const listInvoices = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const state = req.query.status as string | undefined;
    const operator = req.query.operator as string | undefined;
        const id = parseInt((req as any).user!.id, 10);  // parse int para convertir a numero 
    const invoices = await InvoiceService.list(id, state,operator);
    res.json(invoices);
  } catch (err) {
    next(err);
  }
};

const setPaymentCard = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const invoiceId = parseInt(req.params.id, 10);  // parse int para convertir a numero
    const paymentBrand = req.body.paymentBrand;
    const ccNumber = req.body.ccNumber;
    const ccv = req.body.ccv;
    const expirationDate = req.body.expirationDate;

    if (!paymentBrand || !ccNumber || !ccv || !expirationDate) {
      return res.status(400).json({ error: 'Missing payment details' });
    }
    const id = parseInt((req as any).user!.id, 10); //parse unt para convertir a numero 
    await InvoiceService.setPaymentCard(
      id,
      invoiceId,
      paymentBrand,
      ccNumber,
      ccv,
      expirationDate
    );

    res.status(200).json({ message: 'Payment successful' });
  } catch (err) {
    next(err);
  }
};

const getInvoicePDF = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const invoiceId = (req.params.id, 10); 
    const pdfName = req.query.pdfName as string | undefined;

    if (!pdfName) {
      return res.status(400).json({ error: 'Missing parameter pdfName' });
    }

    //obtener el userID del request
    const userId = (req as any).user?.id;
   

    const pdf = await InvoiceService.getReceipt(invoiceId, pdfName, userId);

    // return the pdf as a binary respon
    res.setHeader('Content-Type', 'text/plain'); // cambio a text plain para ver respuesta en Path Traversal
    res.send(pdf);

  } catch (err) {
    next(err);
  }
};

const getInvoice = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const invoiceId = (req.params.id, 10); 
    const userId = ((req as any).user!.id);
    const invoice = await InvoiceService.getInvoice(invoiceId, userId);

    if (!invoice) {
      return res.status(404).json({ error: 'Factura no encontrada o usuario sin autorizacion' }); 
    }

    res.status(200).json(invoice);

  } catch (err) {
    next(err);
  }
};

export default {
  listInvoices,
  setPaymentCard,
  getInvoice,
  getInvoicePDF
};