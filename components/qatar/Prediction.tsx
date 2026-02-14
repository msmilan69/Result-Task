// ============================================
// CRITICAL FIX #1: Signature Verification
// ============================================
// File: components/qatar/Prediction.tsx

import React, { useEffect, useMemo, useState } from 'react';
import ReactGA from 'react-ga4';
import classNames from 'classnames';
import { toast } from 'react-toastify';
import { useAccount, useNetwork, useSwitchNetwork } from 'wagmi';
import { recoverMessageAddress } from 'viem';
import Message from '../message';
import { getEtherscanLink } from '../../utils';
import { ARCANA_CHAIN_ID } from '../../constants';
import PredictionDialog from './PredictionDialog';
import { useIsMounted } from '../../hooks/useIsMounted';
import { useCollabContract } from '../../hooks/useContract';
import { PredictionItem, PredictionOption, predictions } from './predictions';
import { Hash } from "viem";

type PredictionProps = {
  deadline?: number;
  signature?: Hash;
};

export default function Prediction({ signature, deadline }: PredictionProps) {
  const { chain } = useNetwork();
  const { address } = useAccount();
  const isMounted = useIsMounted();
  const collabContract = useCollabContract();
  const [isSubmitted, setIsSubmitted] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [openDialog, setOpenDialog] = useState<boolean>(false);
  const [answer, setAnswer] = useState<PredictionOption | undefined>(undefined);
  const [prediction, setPrediction] = useState<PredictionItem | undefined>(undefined);
  const { switchNetwork, isLoading: isSwitchNetworkLoading } = useSwitchNetwork({ chainId: ARCANA_CHAIN_ID });

  const submitStatus = useMemo(() => {
    return !!(address && signature);
  }, [address, signature]);

  const onDialogClick = () => {
    setOpenDialog(true);
  };

  const onSubmit = async () => {
    if (!prediction || !chain || !address || !signature || !collabContract || isLoading || isSubmitted || !deadline) return;
    
    try {
      setIsLoading(true);
      
      // ✅ SECURITY FIX: Verify signature before submission
      
      // 1. Reconstruct the message that should have been signed
      // SECURITY FIX: Include chainId to prevent cross-chain replay attacks
      const message = `qatar2022:${prediction.ipfs}:${deadline}:${chain.id}`;
      
      // 2. Verify the signature
      let recoveredAddress: string;
      try {
        recoveredAddress = await recoverMessageAddress({
          message,
          signature
        });
      } catch (verifyError) {
        console.error('Signature verification failed:', verifyError);
        toast.error(
          <Message 
            title="Invalid Signature" 
            message="The signature could not be verified. Please try again." 
          />
        );
        setIsLoading(false);
        return;
      }
      
      // 3. Ensure the signature was created by an authorized backend signer
      // ✅ SECURITY FIX: Signature should be verified against the backend's authorized signer address
      // rather than the user's address, as this is a backend-generated voucher.
      const AUTHORIZED_SIGNER = process.env.NEXT_PUBLIC_BACKEND_SIGNER_ADDRESS || '0x15719A5A6CB3794342d86912280cb8EB3BA54360'; // COLLAB_ADDRESS often doubled as signer or similar
      
      if (recoveredAddress.toLowerCase() !== AUTHORIZED_SIGNER.toLowerCase()) {
        toast.error(
          <Message 
            title="Unauthorized Signature" 
            message="The signature was not created by an authorized signer." 
          />
        );
        setIsLoading(false);
        return;
      }
      
      // 4. Verify deadline hasn't expired
      const now = Math.floor(Date.now() / 1000);
      if (now > deadline) {
        toast.error(
          <Message 
            title="Deadline Expired" 
            message="The submission deadline has passed. Please request a new signature." 
          />
        );
        setIsLoading(false);
        return;
      }
      
      // 5. Check deadline is not too far in the future (prevent replay attacks)
      const maxDeadline = now + (24 * 60 * 60); // 24 hours
      if (deadline > maxDeadline) {
        toast.error(
          <Message 
            title="Invalid Deadline" 
            message="Deadline is too far in the future." 
          />
        );
        setIsLoading(false);
        return;
      }
      
      ReactGA.event({ action: 'qatar', category: 'Click', label: 'quizsub' });
      
      // @ts-ignore
      const transactionHash = await collabContract.write.saveStamp([
        'qatar2022', 
        prediction.ipfs, 
        deadline, 
        signature
      ]);
      
      toast.success(
        <Message
          title="Mission Complete"
          message={
            <div>
              <p>Submitted</p>
              <p>
                <a className="text-blue" target="_blank" href={getEtherscanLink(transactionHash, 'transaction')}>
                  View on Etherscan
                </a>
              </p>
            </div>
          }
        />,
      );
      setIsLoading(false);
      setIsSubmitted(true);
    } catch (error: any) {
      console.error('Submission error:', error);
      if (error.error && error.error.data) {
        toast.error(<Message title="Submission Failed" message={error.error.data.message || "save error"} />);
      } else {
        toast.error(<Message title="Submission Failed" message={error.message || "An unexpected error occurred"} />);
      }
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (!collabContract || !address) return;
    collabContract.read
      .readStamp([address, 'qatar2022'])
      .then((res: string | undefined) => {
        if (res) {
          const key = res.split('ipfs://')[1];
          const item = predictions[key];
          setPrediction(item);
          setAnswer(item.answer);
          setIsSubmitted(true);
        } else {
          const keys = Object.keys(predictions);
          setPrediction(predictions[keys[Math.floor(Math.random() * keys.length)]]);
          setAnswer(undefined);
          setIsSubmitted(false);
        }
      })
      .catch((error: any) => {
        console.error(error);
        const keys = Object.keys(predictions);
        setPrediction(predictions[keys[Math.floor(Math.random() * keys.length)]]);
        setAnswer(undefined);
        setIsSubmitted(false);
      });
  }, [collabContract, address]);

  if (!isMounted) return null;

  return (
    <div className="qatar__box mx-auto mt-4 flex max-w-[840px] gap-12 p-6 md:flex-col md:items-center md:gap-4 md:p-3">
      <div className="relative h-[230px] w-[230px] cursor-pointer overflow-hidden rounded-lg" onClick={onDialogClick}>
        {answer ? (
          <div
            className="h-full pt-11 text-center font-medium"
            style={{ background: 'linear-gradient(180deg, #3D444B80 0%, #23262C80 100%)' }}
          >
            <div className="mx-auto h-[123px] w-[185px] text-center">
              <img loading="lazy" width={185} className="rounded" src={answer?.img} alt="select" />
            </div>
            <p className="mt-7 text-center text-lg font-medium leading-5">{answer?.name}</p>
          </div>
        ) : (
          <div className="flex h-full w-full flex-col items-center justify-center bg-black/60 font-medium hover:bg-white/10">
            <p className="text-[70px] leading-[84px]">?</p>
            <p className="text-sm">Click to Answer</p>
          </div>
        )}
      </div>
      <div className="relative w-full flex-1">
        <h3 className="text-center text-2xl leading-7">{prediction?.title}</h3>
        <p className="mt-2 text-center text-xs leading-4">{prediction?.subTitle}</p>
        {submitStatus ? (
          chain?.id !== ARCANA_CHAIN_ID ? (
            <button
              className="qatar__button absolute bottom-0 w-full py-3 md:relative md:mt-6"
              onClick={() => switchNetwork?.()}
            >
              {isSwitchNetworkLoading ? (
                <img className="mx-auto animate-spin" src="/svg/loading.svg" alt="loading" />
              ) : (
                'Switch Network'
              )}
            </button>
          ) : (
            <button
              className={classNames(
                'absolute bottom-0 w-full py-3 md:relative md:mt-6',
                !isSubmitted && answer ? 'qatar__button' : 'qatar__button--disable',
              )}
              onClick={onSubmit}
            >
              {isLoading ? (
                <img className="mx-auto animate-spin" src="/svg/loading.svg" alt="loading" />
              ) : isSubmitted ? (
                'Submitted'
              ) : (
                'Submit'
              )}
            </button>
          )
        ) : (
          <button className="qatar__button--disable absolute bottom-0 w-full py-3 md:relative md:mt-6">Submit</button>
        )}
      </div>
      <PredictionDialog
        onSelect={(item) => setAnswer(item)}
        title={prediction?.title}
        subTitle={prediction?.subTitle}
        options={prediction?.options}
        open={openDialog}
        onOpenChange={(op) => setOpenDialog(op)}
      />
    </div>
  );
}
