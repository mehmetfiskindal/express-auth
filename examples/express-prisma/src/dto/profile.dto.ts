/**
 * User Profile DTOs
 */

export class ProfileResponse {
  message!: string;
  userId!: string;
  email!: string;
  roles!: string[];
}

export class AdminDataResponse {
  message!: string;
  secret!: string;
}

export class PublicDataResponse {
  message!: string;
}
