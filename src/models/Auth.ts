import { model, Schema, Document } from "mongoose";

export interface IAuth extends Document {
  phone: string;
  password: string;
}

const AuthSchema = new Schema<IAuth>(
  {
    phone: { type: String, required: true },
    password: { type: String, required: true },
  },
  {
    timestamps: true,
  }
);

const Auth = model<IAuth>("Auth", AuthSchema);

export default Auth;
