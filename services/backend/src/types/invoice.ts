export interface Invoice {
    id: number;     //cambio a number
    userId: number; //cambio a number
    amount: number;
    dueDate: Date;
    status: string;
}