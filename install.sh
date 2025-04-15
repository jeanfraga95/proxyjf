const { Telegraf } = require('telegraf');
const MercadoPago = require('mercadopago');
const fs = require('fs');
const QRCode = require('qrcode-terminal');
const express = require('express');

// Configurar o Mercado Pago com o seu Access Token
MercadoPago.configurations.setAccessToken('APP_USR-2895308821549951-101213-dd741d1833986338f8bbb516b979e643-273879961');

// Inicializando o bot com o token do Telegram
const bot = new Telegraf('7784490351:AAGoLCHPZJNhX6OM4LGdlr72p72CqKnWxT4');

// Caminho do arquivo onde os saldos dos usuários serão armazenados
const saldoFile = './saldos.json';

// Função para carregar os saldos dos usuários
function loadSaldos() {
  try {
    return JSON.parse(fs.readFileSync(saldoFile));
  } catch (error) {
    return {};
  }
}

// Função para salvar os saldos dos usuários
function saveSaldos(saldos) {
  fs.writeFileSync(saldoFile, JSON.stringify(saldos, null, 2));
}

// Função para verificar se o usuário tem saldo suficiente
function hasSufficientBalance(userId, amount) {
  const saldos = loadSaldos();
  return saldos[userId] && saldos[userId] >= amount;
}

// Comando /start
bot.start(async (ctx) => {
  const userId = ctx.from.id;
  const saldos = loadSaldos();

  if (!saldos[userId]) {
    saldos[userId] = 0;
    saveSaldos(saldos);
  }

  if (saldos[userId] === 0) {
    await ctx.reply('Você não tem saldo. Use /adicionar para adicionar saldo ao seu bot.');
  } else {
    await ctx.reply('Escolha o plano de internet que deseja:\n1. 420GB (14GB Diários)\n2. 840GB (28GB Diários)');
  }
});

// Comando /adicionar
bot.command('adicionar', async (ctx) => {
  const userId = ctx.from.id;
  const saldos = loadSaldos();

  // Pergunta os valores de saldo disponíveis
  const resposta = await ctx.reply(
    'Escolha o valor que deseja adicionar ao seu saldo:\n1. R$ 10 (100GB)\n2. R$ 20 (200GB)\n3. R$ 50 (500GB)'
  );

  bot.on('text', async (ctx) => {
    if (ctx.message.text === '1') {
      await gerarQRCode(ctx, 10);
    } else if (ctx.message.text === '2') {
      await gerarQRCode(ctx, 20);
    } else if (ctx.message.text === '3') {
      await gerarQRCode(ctx, 50);
    }
  });
});

// Função para gerar o QR Code do Mercado Pago
async function gerarQRCode(ctx, valor) {
  const preference = {
    items: [
      {
        title: 'Adicionar Saldo',
        quantity: 1,
        currency_id: 'BRL',
        unit_price: valor,
      },
    ],
    // Não estamos usando back_urls, pois vamos tratar tudo no bot
    auto_return: 'approved',
  };

  // Criar a preferência de pagamento no Mercado Pago
  const response = await MercadoPago.preferences.create(preference);
  const qrCodeUrl = response.body.init_point;

  // Gerar QR Code para o pagamento
  QRCode.generate(qrCodeUrl, { small: true }, (qrcode) => {
    ctx.reply(`Para adicionar R$ ${valor}, faça o pagamento pelo QR Code abaixo:\n${qrcode}`);
  });
}

// Função para verificar o status de pagamento
async function verificarPagamento(paymentId) {
  try {
    const payment = await MercadoPago.payment.findById(paymentId);
    return payment.body.status === 'approved'; // Status do pagamento
  } catch (error) {
    console.error('Erro ao verificar o pagamento:', error);
    return false;
  }
}

// Webhook para o Mercado Pago
const app = express();
app.post('/webhook', express.json(), async (req, res) => {
  const paymentId = req.body.data.id;
  const userId = req.body.data.external_reference; // O ID do usuário pode ser armazenado como referência externa

  const pagamentoConfirmado = await verificarPagamento(paymentId);

  if (pagamentoConfirmado) {
    const saldos = loadSaldos();
    const valorPago = req.body.data.transaction_amount; // O valor pago

    // Atualizar o saldo do usuário
    if (!saldos[userId]) {
      saldos[userId] = 0;
    }
    saldos[userId] += valorPago;
    saveSaldos(saldos);

    // Enviar notificação para o usuário
    bot.telegram.sendMessage(userId, `Pagamento confirmado! Seu saldo foi atualizado para R$ ${saldos[userId]}.`);
  } else {
    // Caso o pagamento não tenha sido aprovado
    bot.telegram.sendMessage(userId, 'O pagamento não foi aprovado. Tente novamente.');
  }

  res.status(200).send('OK');
});

// Comando /adquirir_plano
bot.command('adquirir_plano', async (ctx) => {
  const userId = ctx.from.id;
  const saldos = loadSaldos();

  if (!saldos[userId] || saldos[userId] === 0) {
    return ctx.reply('Você não tem saldo suficiente para adquirir um plano. Adicione saldo primeiro usando /adicionar.');
  }

  const plano = ctx.message.text.split(' ')[1]; // Exemplo de comando: /adquirir_plano 1
  let valorPlano = 0;

  if (plano === '1') valorPlano = 10; // Exemplo de plano 1
  if (plano === '2') valorPlano = 20; // Exemplo de plano 2
  if (plano === '3') valorPlano = 50; // Exemplo de plano 3

  if (hasSufficientBalance(userId, valorPlano)) {
    saldos[userId] -= valorPlano;
    saveSaldos(saldos);
    ctx.reply(`Plano adquirido com sucesso! Seu novo saldo é R$ ${saldos[userId]}.`);
  } else {
    ctx.reply('Saldo insuficiente para adquirir o plano selecionado.');
  }
});

// Função para realizar o envio dos GBs Diários para o admin
function sendDailyGbsToAdmin() {
  const saldos = loadSaldos();
  const adminId = '6545767383'; // Substitua com o ID do admin

  for (const userId in saldos) {
    const saldo = saldos[userId];
    // Aqui você pode definir as lógicas de envio de GB diários.
    bot.telegram.sendMessage(adminId, `Usuário ${userId} tem ${saldo} GB restantes.`);
  }
}

// Configurar função de admin para adicionar usuários ilimitados
let adminUsers = []; // Lista de IDs de usuários ilimitados
bot.command('add_admin', (ctx) => {
  const userId = ctx.from.id;

  if (userId === '6545767383') {
    const args = ctx.message.text.split(' ');
    const userToAdd = args[1];
    adminUsers.push(userToAdd);
    ctx.reply(`Usuário ${userToAdd} adicionado como admin.`);
  } else {
    ctx.reply('Você não tem permissão para adicionar admins.');
  }
});

// Função para verificar se o usuário está no plano ilimitado
function isUnlimitedUser(userId) {
  return adminUsers.includes(userId);
}

// Função para subtrair saldo ao comprar um plano
async function processarCompraPlano(userId, valorPlano) {
  const saldos = loadSaldos();

  if (!hasSufficientBalance(userId, valorPlano)) {
    return 'Saldo insuficiente para adquirir o plano.';
  }

  saldos[userId] -= valorPlano;
  saveSaldos(saldos);

  return 'Plano adquirido com sucesso!';
}

// Definindo a lógica diária de notificação
setInterval(sendDailyGbsToAdmin, 24 * 60 * 60 * 1000); // Envia a cada 24 horas

// Iniciando o servidor para o Webhook
app.listen(3000, () => {
  console.log('Servidor webhook iniciado na porta 3000');
});

// Iniciando o bot
bot.launch();
