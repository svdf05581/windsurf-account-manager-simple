import { invoke } from '@tauri-apps/api/core';

export interface VirtualCard {
  card_number: string;
  expiry_date: string;
  cvv: string;
  cardholder_name: string;
  billing_address: BillingAddress;
}

export interface BillingAddress {
  street_address: string;
  street_address_line2: string;  // 地址第二行
  city: string;
  state: string;
  postal_code: string;
  country: string;
}

/**
 * 生成虚拟信用卡信息
 */
export async function generateVirtualCard(): Promise<VirtualCard> {
  return await invoke<VirtualCard>('generate_virtual_card');
}

/**
 * 验证卡号是否符合Luhn算法
 */
export async function validateCardNumber(cardNumber: string): Promise<boolean> {
  return await invoke<boolean>('validate_card_number', { cardNumber });
}

/**
 * 获取试用支付链接（增强版）
 *
 * `accountId` 用于让后端按账号 ID 查库并构造完整的 AuthContext，
 * 这样 Devin 账号也能正确附带 `x-devin-*` 扩展 header，避免"Devin 获取支付链接老是失败"。
 */
export async function getTrialPaymentLink(
  accountName: string,
  token: string,
  autoOpen: boolean,
  teamsTier: number,
  paymentPeriod: number,
  startTrial: boolean,
  teamName?: string,
  seatCount?: number,
  turnstileToken?: string,
  accountId?: string
): Promise<any> {
  return await invoke('get_trial_payment_link_enhanced', {
    accountName,
    token,
    autoOpen,
    teamsTier,
    paymentPeriod,
    startTrial,
    teamName,
    seatCount,
    turnstileToken,
    accountId
  });
}

/**
 * 打开支付窗口
 */
export async function openPaymentWindow(
  url: string,
  accountName: string
): Promise<void> {
  return await invoke('open_payment_window', {
    url,
    accountName
  });
}

/**
 * 自动填写支付表单
 */
export async function autoFillPaymentForm(
  windowLabel: string,
  virtualCard?: VirtualCard
): Promise<void> {
  return await invoke('auto_fill_payment_form', {
    windowLabel,
    virtualCard
  });
}

/**
 * 注入卡信息到指定窗口
 */
export async function injectCardInfo(
  windowLabel: string,
  cardInfo: VirtualCard
): Promise<void> {
  return await invoke('inject_card_info', {
    windowLabel,
    cardInfo
  });
}
