import { PublicKey } from "@solana/web3.js";
import bs58 from "bs58";
import nacl from "tweetnacl";

import { unattachGeneralAction } from "../../helpers/unattachAuthAction";
import { validate } from "./validation";

import { EAuthMethods } from "../../../../../consts";
import type { IAuthEngine, ISignupData } from "../../interface";
import type { ISolanaAttachData, ISolanaLoginData } from "./types";

import UserDto from "../../../../../dtos/user-dto";

import { userService } from "../../../../../service";
import authService from "../../../../../service/auth-service";
import tokenService from "../../../../../service/token-service";

import bcrypt from "bcrypt";

import { errors } from "./errors";

const usedNonces = new Map<string, { nonce: string; timestamp: number }>();

export class SolanaAuthEngine implements IAuthEngine {
  method = EAuthMethods.Solana;

  async login({
    referralCode,
    onboardingExpBonus,
    ...data
  }: ISolanaLoginData): ReturnType<IAuthEngine["login"]> {
    validate().login(data);

    this.validateSignature(data);

    const user = await userService
      .getByFilter({
        filter: {
          "authMethods.method": this.method,
          "authMethods.token": data.publicKey,
        },
        select: "address isActivated roles",
      })
      .catch(console.error);

    let userDto: UserDto | null;
    let isNew = false;
    if (user) {
      userDto = new UserDto(user);
    } else {
      userDto = await this.signup({
        token: data.publicKey,
        referralCode: referralCode,
        onboardingExpBonus: onboardingExpBonus,
      });
      isNew = true;
    }

    const tokens = tokenService.generateTokens({ ...userDto });
    await tokenService.saveToken(userDto.id, tokens.refreshToken);

    return { ...tokens, user: userDto, isNew };
  }

  async signup({
    token,
    referralCode,
    onboardingExpBonus,
  }: ISignupData): ReturnType<IAuthEngine["signup"]> {
    return authService.registrationMFA({
      method: this.method,
      token,
      referralCode: referralCode,
      onboardingExpBonus,
    });
  }

  async attach(data: ISolanaAttachData): ReturnType<IAuthEngine["attach"]> {
    const {
      userId,
      data: { origin, ...signUpData },
    } = data;
    validate().attach(data);

    const candidate = await userService
      .getByFilter({
        filter: {
          "authMethods.method": this.method,
          "authMethods.token": signUpData.publicKey,
        },
        select: "",
      })
      .catch(console.error);

    if (candidate) {
      throw errors.METHOD_ALREADY_TAKEN();
    }

    const user = await userService.getByFilter({
      filter: { _id: userId },
      select: "authMethods",
    });

    if (!user.authMethods) {
      user.authMethods = [];
    }

    if (
      !user.authMethods.some(
        (m) => m.method === this.method && m.token === signUpData.publicKey,
      )
    ) {
      user.authMethods.push({
        method: this.method,
        token: signUpData.publicKey,
      });

      await userService.updateByFilter(
        { filter: { _id: userId } },
        { authMethods: user.authMethods },
      );
    }
    return this.login(data.data);
  }

  async logout(): ReturnType<IAuthEngine["logout"]> {
    return;
  }

  async unattach(userId: string): ReturnType<IAuthEngine["unattach"]> {
    return unattachGeneralAction(userId, this.method);
  }

  async generateSignatureMessage(publicKey: string) {
    try {
      const nonce = await bcrypt.hash(
        Math.floor(Math.random() * 1000000000).toString(),
        3,
      );
      usedNonces.set(publicKey, { nonce, timestamp: Date.now() });
      return [
        "Welcome to Mighty!",
        "Please sign this message to authenticate.",
        "This request will not trigger a blockchain transaction or cost any fees.",
        "Wallet address:",
        publicKey,
        "Nonce:",
        nonce,
      ].join("\n\n");
    } catch (error) {
      console.error(error);
      throw errors.FAIL_GENERATE_MESSAGE();
    }
  }

  private validateNonce(publicKey: string) {
    try {
      const nonceData = usedNonces.get(publicKey);
      if (!nonceData) {
        throw errors.NONCE_IS_EXPIRED();
        return;
      }
      const { nonce: storedNonce, timestamp } = nonceData;
      if (Date.now() - timestamp > 1000 * 60) {
        usedNonces.delete(publicKey);
        throw errors.NONCE_IS_EXPIRED();
      }
      return storedNonce;
    } catch (error) {
      throw errors.NONCE_IS_EXPIRED();
    }
  }

  private validateSignature({
    publicKey,
    signature,
    message,
  }: {
    publicKey: string;
    signature: string;
    message: string;
  }) {
    this.validateNonce(publicKey);
    try {
      const messageBytes = new TextEncoder().encode(message);

      const signatureBytes = bs58.decode(signature);

      const pubKeyBytes = new PublicKey(publicKey).toBytes();

      const verified = nacl.sign.detached.verify(
        messageBytes,
        signatureBytes,
        pubKeyBytes,
      );

      if (!verified) {
        throw errors.SIGNATURE_IS_INVALID();
      }
    } catch (error) {
      throw errors.SIGNATURE_IS_INVALID();
    }
  }
}
