export interface UserTalk {
  kind: 'user';
  time: Date;
  talkerId: string;
  content: string;
  arrived: boolean;
}

export interface SystemTalk {
  kind: 'system';
  time: Date;
  content: string;
}

export type Talk = UserTalk | SystemTalk;
