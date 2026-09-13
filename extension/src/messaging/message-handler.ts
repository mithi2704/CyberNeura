/**
 * Message Handler Router for CyberNeura Chrome Extension.
 */

import { ExtensionMessage } from './messages';

export type MessageCallback = (payload: any) => Promise<any> | any;

export class MessageRouter {
  private handlers = new Map<string, MessageCallback>();

  register(type: string, callback: MessageCallback): void {
    this.handlers.set(type, callback);
  }

  async handle(message: ExtensionMessage): Promise<any> {
    const handler = this.handlers.get(message.type);
    if (!handler) {
      throw new Error(`Unrecognized message type: ${message.type}`);
    }
    return await handler(message.payload);
  }
}
