export interface User {
  id?: number;        //cambio a number
  username?: string;  
  email: string;
  password: string;
  first_name: string;
  last_name: string;
}

export interface UserRow {
  id: number;       //cambio a number
  username: string;
  email: string;
  password: string;
  first_name: string;
  last_name: string;
  reset_password_token?: string;
  reset_password_expires?: Date;
  invite_token?: string;
  invite_token_expires?: Date;
  activated: boolean;
}