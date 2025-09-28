import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';

import InvoiceService from '../../src/services/invoiceService';
import db from '../../src/db';
import { Invoice } from '../../src/types/invoice';

jest.mock('../../src/db')
const mockedDb = db as jest.MockedFunction<typeof db>


describe('AuthService.generateJwt', () => {
  beforeEach (() => {
    jest.resetModules();
  });

  beforeAll(() => {
  });

  afterAll(() => {
  });

  it('listInvoices', async () => {
    const userId = 5555;         //cambio de string a nuemero'user-123';
    const state = 'paid';
    const operator = 'eq';
    const mockInvoices: Invoice[] = [
      { id: 1, userId, amount: 100, dueDate: new Date(), status: 'paid' },  //cambio de string a number para los Ids
      { id: 2, userId, amount: 200, dueDate: new Date(), status: 'paid' }
    ];
    // mock no user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      select: jest.fn().mockResolvedValue(mockInvoices),
    };
    mockedDb.mockReturnValue(selectChain as any);

    const invoices = await InvoiceService.list(userId, state, operator);

    expect(mockedDb().where).toHaveBeenCalledWith({ userId });
    expect(mockedDb().andWhere).toHaveBeenCalledWith('state', operator, state);
    expect(mockedDb().select).toHaveBeenCalled();
    expect(invoices).toEqual(mockInvoices);
  });

  it('listInvoices no state', async () => {
    const userId = 5555;         //cambio de string a nuemero'user-123';
    const mockInvoices: Invoice[] = [
      { id: 2, userId, amount: 100, dueDate: new Date(), status: 'paid' },  //cambio de string a number para los Ids
      { id: 3, userId, amount: 200, dueDate: new Date(), status: 'unpaid' }
    ];
    // mock no user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      select: jest.fn().mockResolvedValue(mockInvoices),
    };
    mockedDb.mockReturnValue(selectChain as any);
    const invoices = await InvoiceService.list(userId);

    expect(mockedDb().where).toHaveBeenCalledWith({ userId });
    expect(mockedDb().andWhere).not.toHaveBeenCalled();
    expect(mockedDb().select).toHaveBeenCalled();
    expect(invoices).toEqual(mockInvoices);
  });

});
