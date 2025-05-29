import { useConnection, useWallet } from '@solana/wallet-adapter-react';
import { useWalletModal } from '@solana/wallet-adapter-react-ui';
import { LAMPORTS_PER_SOL } from '@solana/web3.js';
import { useGetUserData } from 'hooks';
import { EAuthMethods } from 'interface';

type Props = {
  incrementTaskCount: () => void;
};

export const useCompleteSolanaTask = ({ incrementTaskCount }: Props) => {
  const { connection } = useConnection();
  const { publicKey: solanaPublicKey, connected: solanaConnected } = useWallet();
  const { setVisible, visible } = useWalletModal();
  const { authMethods = [] } = useGetUserData();
  const SOLANAAuthMethod = authMethods?.find((i) => i.method === EAuthMethods.Solana);
  const SolanaAdress = SOLANAAuthMethod?.token;

  const completeSolanaTask = () => {
    if (!SolanaAdress) {
      return async () => ({ stopAction: 'link-modal--SOLANA', status: false, isStopped: true });
    }

    return async () => {
      try {
        if (!solanaConnected || !solanaPublicKey) {
          if (visible) return;
          setVisible(true);
          return { stopAction: 'link-modal--SOLANA', status: false, isStopped: true };
        }

        const balanceInLamports = await connection.getBalance(solanaPublicKey);
        const balanceInSol = balanceInLamports / LAMPORTS_PER_SOL;

        const hasRequiredBalance = balanceInSol >= 0.1;
        if (hasRequiredBalance) {
          incrementTaskCount();
          return { status: true };
        }
        return { status: false, isStopped: true, stopAction: 'not-enough-sol' };
      } catch (error) {
        console.error('Error checking SOL balance:', error);
        return { status: false };
      }
    };
  };

  return completeSolanaTask;
};
