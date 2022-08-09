interface Error {
  status?: number;
  data?: any;
}

interface ErrorConstructor {
  new (message?: string, status?: number, data?: any): Error;
  (message?: string, status?: number, data?: any): Error;
  readonly prototype: Error;
}

Error.prototype.constructor = function (
  message: string = "",
  status: number | undefined = undefined,
  data: any = undefined
) {
  this.message = message;
  if (status) this.status = status;
  if (data) this.data = data;
  return this;
};

interface RemoveEmptyOptions {
  keepEmpty?: boolean;
  keepNull?: boolean;
  keepUndefined?: boolean;
}
