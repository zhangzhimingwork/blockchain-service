const crypto = require('crypto')
const express = require('express')

const app = express()
const cors = require('cors')

// CORS配置
const corsOptions = {
  origin: [
    'http://localhost:3001', // React开发服务器
    'http://localhost:3002' // 如果前端也在3002端口
    // 'https://your-frontend-domain.com' // 生产环境域名
  ],
  credentials: true, // 允许携带凭证
  optionsSuccessStatus: 200
}

app.use(cors(corsOptions))
app.use(express.json())

//1.能够代币的生产
//2.能够新建一个用户
//3.能够完成代币的转账
//4.矿工
//5.有基本区块链浏览器能够查看当前的块高度的还有区块信息

// 交易类
class Transaction {
  /**
   * 交易构造函数
   * 作用：创建一个新的交易对象
   * 与以太坊差异：
   * - 以太坊交易包含gas、gasPrice、nonce等字段
   * - 以太坊支持智能合约调用（data字段）
   * - 以太坊有更复杂的交易类型（Legacy、EIP-1559等）
   */
  constructor(fromAddress, toAddress, amount) {
    this.fromAddress = fromAddress
    this.toAddress = toAddress
    this.amount = amount
    this.timestamp = Date.now()
    this.hash = this.calculateHash()
  }

  /**
   * 计算交易哈希
   * 作用：为交易生成唯一标识符
   * 与以太坊差异：
   * - 以太坊使用Keccak-256而非SHA-256
   * - 以太坊交易哈希包含更多字段（nonce、gasPrice、gasLimit等）
   * - 以太坊使用RLP编码而非简单字符串拼接
   */
  calculateHash() {
    return crypto
      .createHash('sha256')
      .update(this.fromAddress + this.toAddress + this.amount + this.timestamp)
      .digest('hex')
  }

  /**
   * 签署交易
   * 作用：使用私钥对交易进行数字签名，证明交易发起者身份
   * 与以太坊差异：
   * - 以太坊使用secp256k1椭圆曲线（相同）
   * - 以太坊签名包含v、r、s三个部分
   * - 以太坊支持EIP-155重放攻击保护
   */
  signTransaction(signingKey) {
    if (signingKey.getPublic('hex') !== this.fromAddress) {
      throw new Error('你不能为其他钱包签署交易！')
    }

    const hashTx = this.calculateHash()
    const sig = signingKey.sign(hashTx, 'base64')
    this.signature = sig.toDER('hex')
  }

  /**
   * 验证交易有效性
   * 作用：检查交易签名是否正确，确保交易未被篡改
   * 与以太坊差异：
   * - 以太坊还会验证nonce顺序、gas费用等
   * - 以太坊有更复杂的交易验证规则
   * - 以太坊支持智能合约执行前的预验证
   */
  isValid() {
    if (this.fromAddress === null) return true // 挖矿奖励交易

    if (!this.signature || this.signature.length === 0) {
      throw new Error('此交易没有签名')
    }

    const EC = require('elliptic').ec
    const ec = new EC('secp256k1')
    const publicKey = ec.keyFromPublic(this.fromAddress, 'hex')

    return publicKey.verify(this.calculateHash(), this.signature)
  }
}

// 区块类
class Block {
  /**
   * 区块构造函数
   * 作用：创建一个新的区块
   * 与以太坊差异：
   * - 以太坊区块包含更多字段：gasLimit、gasUsed、difficulty、extraData等
   * - 以太坊有状态根、交易根、收据根（Merkle树）
   * - 以太坊区块大小有gas限制而非固定交易数量
   */
  constructor(timestamp, transactions, previousHash = '') {
    this.previousHash = previousHash
    this.timestamp = timestamp
    this.transactions = transactions
    this.nonce = 0
    this.hash = this.calculateHash()
  }

  /**
   * 计算区块哈希
   * 作用：生成区块的唯一标识符
   * 与以太坊差异：
   * - 以太坊使用Keccak-256哈希算法
   * - 以太坊区块头包含更多字段进行哈希
   * - 以太坊使用RLP编码结构化数据
   */
  calculateHash() {
    return crypto
      .createHash('sha256')
      .update(this.previousHash + this.timestamp + JSON.stringify(this.transactions) + this.nonce)
      .digest('hex')
  }

  /**
   * 挖矿函数（工作量证明）
   * 作用：通过不断调整nonce值找到满足难度要求的哈希
   * 与以太坊差异：
   * - 以太坊已转向权益证明（PoS），不再使用PoW
   * - 以太坊PoW时期使用Ethash算法，抗ASIC
   * - 以太坊难度调整更复杂，考虑出块时间和uncle blocks
   */
  mineBlock(difficulty) {
    const target = Array(difficulty + 1).join('0')

    console.log('开始挖矿...')
    const startTime = Date.now()

    while (this.hash.substring(0, difficulty) !== target) {
      this.nonce++
      this.hash = this.calculateHash()
    }

    const endTime = Date.now()
    console.log(`区块挖掘完成: ${this.hash}`)
    console.log(`挖矿耗时: ${endTime - startTime}ms`)
    console.log(`尝试次数: ${this.nonce}`)
  }

  /**
   * 验证区块中所有交易的有效性
   * 作用：确保区块中包含的所有交易都是有效的
   * 与以太坊差异：
   * - 以太坊还会验证gas使用、状态转换等
   * - 以太坊支持智能合约执行验证
   * - 以太坊有更复杂的交易执行和验证流程
   */
  hasValidTransactions() {
    for (const tx of this.transactions) {
      if (!tx.isValid()) {
        return false
      }
    }
    return true
  }
}

// 用户类（钱包 + 挖矿功能）
class User {
  /**
   * 用户构造函数
   * 作用：创建一个新用户，自动生成密钥对和地址，包含挖矿统计
   * 与以太坊差异：
   * - 以太坊地址是公钥的Keccak-256哈希的后20字节
   * - 以太坊支持助记词和分层确定性钱包（HD Wallet）
   * - 以太坊地址有校验和格式（EIP-55）
   */
  constructor(name) {
    const EC = require('elliptic').ec
    const ec = new EC('secp256k1')

    this.name = name
    this.keyPair = ec.genKeyPair()
    this.publicKey = this.keyPair.getPublic('hex')
    this.privateKey = this.keyPair.getPrivate('hex')
    this.address = this.publicKey // 使用公钥作为地址
    
    // 挖矿统计
    this.miningCount = 0
    this.totalRewards = 0
  }

  /**
   * 获取用户余额
   * 作用：计算用户当前的代币余额
   * 与以太坊差异：
   * - 以太坊使用账户模型，余额直接存储在状态中
   * - 此实现使用UTXO类似模型，需要遍历所有交易计算
   * - 以太坊查询余额更高效
   */
  getBalance(blockchain) {
    return blockchain.getBalanceOfAddress(this.address)
  }

  /**
   * 发送代币
   * 作用：创建并签署一笔转账交易
   * 与以太坊差异：
   * - 以太坊需要指定gas相关参数
   * - 以太坊有nonce管理防止重放攻击
   * - 以太坊支持合约调用和数据传递
   */
  sendMoney(amount, toAddress, blockchain) {
    const transaction = new Transaction(this.address, toAddress, amount)
    transaction.signTransaction(this.keyPair)
    blockchain.addTransaction(transaction)
  }

  /**
   * 开始挖矿
   * 作用：用户作为矿工执行挖矿过程，获取挖矿奖励
   * 与以太坊差异：
   * - 以太坊PoS中验证者按照质押比例随机选择
   * - 以太坊有复杂的奖励计算和分配机制
   * - 以太坊支持MEV（最大可提取价值）
   */
  startMining(blockchain) {
    console.log(`\n=== 用户 ${this.name} 开始挖矿 ===`)

    if (blockchain.pendingTransactions.length === 0) {
      console.log('没有待处理的交易，创建一个空区块')
    }

    const balanceBefore = this.getBalance(blockchain)

    // 开始挖矿
    blockchain.minePendingTransactions(this.address)

    const balanceAfter = this.getBalance(blockchain)
    const reward = balanceAfter - balanceBefore

    this.miningCount++
    this.totalRewards += reward

    console.log(`用户 ${this.name} 获得奖励: ${reward} 代币`)
    console.log(`当前余额: ${balanceAfter} 代币`)
    console.log(`总挖矿次数: ${this.miningCount}`)
    console.log(`累计奖励: ${this.totalRewards} 代币`)

    return {
      reward,
      newBalance: balanceAfter,
      miningCount: this.miningCount,
      totalRewards: this.totalRewards
    }
  }

  /**
   * 获取用户统计信息（包含挖矿统计）
   * 作用：返回用户的详细统计数据
   * 与以太坊差异：
   * - 以太坊验证者有更复杂的性能指标
   * - 以太坊有证明有效性和及时性统计
   * - 以太坊支持验证者评分和声誉系统
   */
  getStats(blockchain) {
    return {
      name: this.name,
      address: this.address,
      publicKey: this.publicKey,
      balance: this.getBalance(blockchain),
      miningCount: this.miningCount,
      totalRewards: this.totalRewards
    }
  }
}

// 区块链类
class Blockchain {
  /**
   * 区块链构造函数
   * 作用：初始化区块链，创建创世区块
   * 与以太坊差异：
   * - 以太坊有预分配的账户和复杂的创世状态
   * - 以太坊支持多种共识机制
   * - 以太坊有更复杂的网络参数配置
   */
  constructor() {
    this.chain = [this.createGenesisBlock()]
    this.difficulty = 2
    this.pendingTransactions = []
    this.miningReward = 100
    this.totalSupply = 0
  }

  /**
   * 创建创世区块
   * 作用：创建区块链的第一个区块
   * 与以太坊差异：
   * - 以太坊创世区块包含预分配余额、合约代码等
   * - 以太坊创世区块有更复杂的初始状态
   * - 以太坊支持硬分叉配置
   */
  createGenesisBlock() {
    const genesisBlock = new Block(Date.now(), [], '0')
    console.log('创世区块已创建')
    return genesisBlock
  }

  /**
   * 获取最新区块
   * 作用：返回区块链中的最后一个区块
   * 与以太坊差异：基本相同，但以太坊还区分最新区块和安全区块
   */
  getLatestBlock() {
    return this.chain[this.chain.length - 1]
  }

  /**
   * 挖矿处理待确认交易（代币生产）
   * 作用：将待处理交易打包成区块并挖矿，同时产生新代币作为奖励
   * 与以太坊差异：
   * - 以太坊PoS中验证者被随机选择，不需要挖矿
   * - 以太坊有gas费用机制和EIP-1559费用销毁
   * - 以太坊出块时间固定约12秒
   */
  minePendingTransactions(miningRewardAddress) {
    // 创建挖矿奖励交易
    const rewardTransaction = new Transaction(null, miningRewardAddress, this.miningReward)
    this.pendingTransactions.push(rewardTransaction)

    // 创建新区块
    const block = new Block(Date.now(), this.pendingTransactions, this.getLatestBlock().hash)

    // 挖矿
    block.mineBlock(this.difficulty)

    console.log('区块挖掘成功！')
    this.chain.push(block)

    // 增加代币总供应量
    this.totalSupply += this.miningReward
    console.log(`代币总供应量增加: +${this.miningReward}, 当前总量: ${this.totalSupply}`)

    // 清空待处理交易
    this.pendingTransactions = []
  }

  /**
   * 添加交易到待处理队列
   * 作用：验证交易有效性并加入等待挖矿的交易池
   * 与以太坊差异：
   * - 以太坊有复杂的交易池管理和优先级排序
   * - 以太坊基于gas价格确定交易优先级
   * - 以太坊有交易替换和加速机制
   */
  addTransaction(transaction) {
    if (!transaction.fromAddress || !transaction.toAddress) {
      throw new Error('交易必须包含发送和接收地址')
    }

    if (!transaction.isValid()) {
      throw new Error('无法添加无效交易到链中')
    }

    if (transaction.amount <= 0) {
      throw new Error('交易金额应该大于0')
    }

    // 检查发送者余额（挖矿奖励交易除外）
    if (transaction.fromAddress !== null) {
      const walletBalance = this.getBalanceOfAddress(transaction.fromAddress)
      if (walletBalance < transaction.amount) {
        throw new Error('余额不足')
      }
    }

    this.pendingTransactions.push(transaction)
    console.log('交易添加到待处理队列')
  }

  /**
   * 获取地址余额
   * 作用：通过遍历所有交易计算指定地址的当前余额
   * 与以太坊差异：
   * - 以太坊使用账户模型，余额直接存储，查询O(1)
   * - 此实现类似比特币UTXO，需要遍历历史，查询O(n)
   * - 以太坊支持智能合约余额查询
   */
  getBalanceOfAddress(address) {
    let balance = 0

    for (const block of this.chain) {
      for (const trans of block.transactions) {
        if (trans.fromAddress === address) {
          balance -= trans.amount
        }

        if (trans.toAddress === address) {
          balance += trans.amount
        }
      }
    }

    return balance
  }

  /**
   * 获取所有交易记录
   * 作用：返回区块链中所有交易的详细信息
   * 与以太坊差异：
   * - 以太坊有更丰富的交易字段和状态信息
   * - 以太坊支持内部交易和事件日志
   * - 以太坊有交易收据和执行结果
   */
  getAllTransactions() {
    const allTransactions = []
    for (const block of this.chain) {
      for (const trans of block.transactions) {
        allTransactions.push({
          hash: trans.hash,
          from: trans.fromAddress,
          to: trans.toAddress,
          amount: trans.amount,
          timestamp: trans.timestamp,
          blockHash: block.hash
        })
      }
    }
    return allTransactions
  }

  /**
   * 验证区块链完整性
   * 作用：检查整个区块链是否有效，未被篡改
   * 与以太坊差异：
   * - 以太坊还需验证状态根、交易根等Merkle树
   * - 以太坊有更复杂的共识规则验证
   * - 以太坊支持轻客户端验证
   */
  isChainValid() {
    for (let i = 1; i < this.chain.length; i++) {
      const currentBlock = this.chain[i]
      const previousBlock = this.chain[i - 1]

      if (!currentBlock.hasValidTransactions()) {
        return false
      }

      if (currentBlock.hash !== currentBlock.calculateHash()) {
        return false
      }

      if (currentBlock.previousHash !== previousBlock.hash) {
        return false
      }
    }

    return true
  }
}

// 全局区块链实例和用户存储
const globalBlockchain = new Blockchain()
const users = new Map() // 存储用户实例

// =========================== API 接口 ===========================

/**
 * API: 创建新用户（钱包）
 * 作用：生成新的用户钱包，返回地址和必要信息
 * 与以太坊差异：以太坊钱包通常在客户端生成，支持助记词
 */
app.post('/api/wallet/create', (req, res) => {
  try {
    const { name } = req.body

    if (!name) {
      return res.status(400).json({ error: '用户名是必需的' })
    }

    const user = new User(name)
    users.set(user.address, user)

    res.json({
      success: true,
      data: {
        name: user.name,
        address: user.address,
        publicKey: user.publicKey,
        balance: 0,
        miningCount: 0,
        totalRewards: 0
      }
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

/**
 * API: 获取所有用户
 * 作用：返回所有已创建的用户列表
 */
app.get('/api/users', (req, res) => {
  try {
    const usersList = Array.from(users.values()).map(user => user.getStats(globalBlockchain))

    res.json({
      success: true,
      data: usersList
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

/**
 * API: 获取钱包余额
 * 作用：查询指定地址的代币余额
 */
app.get('/api/wallet/:address/balance', (req, res) => {
  try {
    const { address } = req.params
    const balance = globalBlockchain.getBalanceOfAddress(address)

    res.json({
      success: true,
      data: {
        address: address,
        balance: balance
      }
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

/**
 * API: 开始挖矿（代币生产）
 * 作用：指定用户执行挖矿过程，处理待确认交易并获得代币奖励
 */
app.post('/api/mine', (req, res) => {
  try {
    const { userAddress } = req.body

    if (!userAddress) {
      return res.status(400).json({ error: '用户地址是必需的' })
    }

    const user = users.get(userAddress)
    if (!user) {
      return res.status(404).json({ error: '用户不存在' })
    }

    // 挖矿前的状态
    const blocksBefore = globalBlockchain.chain.length

    // 执行挖矿
    const miningResult = user.startMining(globalBlockchain)

    // 挖矿后的状态
    const blocksAfter = globalBlockchain.chain.length

    res.json({
      success: true,
      data: {
        userName: user.name,
        userAddress: userAddress,
        reward: miningResult.reward,
        newBalance: miningResult.newBalance,
        blocksCreated: blocksAfter - blocksBefore,
        totalSupply: globalBlockchain.totalSupply,
        userStats: {
          miningCount: miningResult.miningCount,
          totalRewards: miningResult.totalRewards
        }
      }
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

/**
 * API: 发起转账
 * 作用：创建转账交易并添加到待处理队列
 */
app.post('/api/transfer', (req, res) => {
  try {
    const { fromAddress, toAddress, amount } = req.body

    if (!fromAddress || !toAddress || !amount) {
      return res.status(400).json({ error: '发送地址、接收地址和金额都是必需的' })
    }

    if (amount <= 0) {
      return res.status(400).json({ error: '转账金额必须大于0' })
    }

    // 查找发送者
    const sender = users.get(fromAddress)
    if (!sender) {
      return res.status(404).json({ error: '发送者不存在' })
    }

    // 执行转账
    sender.sendMoney(amount, toAddress, globalBlockchain)

    res.json({
      success: true,
      data: {
        from: fromAddress,
        to: toAddress,
        amount: amount,
        status: '待确认',
        pendingTransactions: globalBlockchain.pendingTransactions.length
      }
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

/**
 * API: 获取区块链信息
 * 作用：返回区块链的基本统计信息
 */
app.get('/api/blockchain/info', (req, res) => {
  try {
    const latestBlock = globalBlockchain.getLatestBlock()

    res.json({
      success: true,
      data: {
        totalBlocks: globalBlockchain.chain.length,
        totalSupply: globalBlockchain.totalSupply,
        difficulty: globalBlockchain.difficulty,
        miningReward: globalBlockchain.miningReward,
        pendingTransactions: globalBlockchain.pendingTransactions.length,
        isValid: globalBlockchain.isChainValid(),
        totalUsers: users.size,
        latestBlock: {
          hash: latestBlock.hash,
          timestamp: latestBlock.timestamp,
          transactionCount: latestBlock.transactions.length,
          previousHash: latestBlock.previousHash
        }
      }
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

/**
 * API: 获取所有区块
 * 作用：返回区块链中所有区块的信息
 */
app.get('/api/blockchain/blocks', (req, res) => {
  try {
    const blocks = globalBlockchain.chain.map((block, index) => ({
      index: index,
      hash: block.hash,
      previousHash: block.previousHash,
      timestamp: block.timestamp,
      transactionCount: block.transactions.length,
      nonce: block.nonce
    }))

    res.json({
      success: true,
      data: blocks
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

/**
 * API: 获取指定区块详情
 * 作用：返回指定索引区块的详细信息
 */
app.get('/api/blockchain/block/:index', (req, res) => {
  try {
    const index = parseInt(req.params.index)

    if (index < 0 || index >= globalBlockchain.chain.length) {
      return res.status(404).json({ error: '区块不存在' })
    }

    const block = globalBlockchain.chain[index]

    res.json({
      success: true,
      data: {
        index: index,
        hash: block.hash,
        previousHash: block.previousHash,
        timestamp: block.timestamp,
        nonce: block.nonce,
        transactions: block.transactions.map((tx) => ({
          hash: tx.hash,
          from: tx.fromAddress,
          to: tx.toAddress,
          amount: tx.amount,
          timestamp: tx.timestamp
        }))
      }
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

/**
 * API: 获取所有交易记录
 * 作用：返回区块链中所有交易的列表
 */
app.get('/api/transactions', (req, res) => {
  try {
    const transactions = globalBlockchain.getAllTransactions()

    res.json({
      success: true,
      data: transactions
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

/**
 * API: 获取待确认交易
 * 作用：返回当前待处理的交易列表
 */
app.get('/api/transactions/pending', (req, res) => {
  try {
    const pendingTx = globalBlockchain.pendingTransactions.map((tx) => ({
      hash: tx.hash,
      from: tx.fromAddress,
      to: tx.toAddress,
      amount: tx.amount,
      timestamp: tx.timestamp
    }))

    res.json({
      success: true,
      data: pendingTx
    })
  } catch (error) {
    res.status(500).json({ error: error.message })
  }
})

// 启动服务器
const PORT = process.env.PORT || 3001
app.listen(PORT, () => {
  console.log(`区块链API服务器运行在端口 ${PORT}`)
  console.log(`\n=== API 端点列表 ===`)
  console.log(`POST /api/wallet/create - 创建用户钱包`)
  console.log(`GET  /api/users - 获取所有用户`)
  console.log(`GET  /api/wallet/:address/balance - 查询余额`)
  console.log(`POST /api/mine - 开始挖矿（代币生产）`)
  console.log(`POST /api/transfer - 发起转账`)
  console.log(`GET  /api/blockchain/info - 获取区块链信息`)
  console.log(`GET  /api/blockchain/blocks - 获取所有区块`)
  console.log(`GET  /api/blockchain/block/:index - 获取指定区块详情`)
  console.log(`GET  /api/transactions - 获取所有交易记录`)
  console.log(`GET  /api/transactions/pending - 获取待确认交易`)
  console.log(`\n访问 http://localhost:${PORT} 开始使用API\n`)
})

// 根路径返回API文档
app.get('/', (req, res) => {
  res.json({
    message: '区块链API服务',
    version: '2.0.0',
    description: '简化版区块链 - 所有用户都可以作为矿工进行挖矿',
    endpoints: {
      wallet: {
        'POST /api/wallet/create': '创建用户钱包 - body: {name: string}',
        'GET /api/users': '获取所有用户列表',
        'GET /api/wallet/:address/balance': '查询指定地址余额'
      },
      mining: {
        'POST /api/mine': '开始挖矿 - body: {userAddress: string}'
      },
      transaction: {
        'POST /api/transfer':
          '发起转账 - body: {fromAddress: string, toAddress: string, amount: number}',
        'GET /api/transactions': '获取所有交易记录',
        'GET /api/transactions/pending': '获取待确认交易'
      },
      blockchain: {
        'GET /api/blockchain/info': '获取区块链基本信息',
        'GET /api/blockchain/blocks': '获取所有区块列表',
        'GET /api/blockchain/block/:index': '获取指定区块详情'
      }
    },
    usage_example: {
      '1. 创建用户': 'POST /api/wallet/create {"name": "Alice"}',
      '2. 查看所有用户': 'GET /api/users',
      '3. 用户挖矿产生代币': 'POST /api/mine {"userAddress": "用户地址"}',
      '4. 转账':
        'POST /api/transfer {"fromAddress": "发送方地址", "toAddress": "接收方地址", "amount": 50}',
      '5. 查询余额': 'GET /api/wallet/地址/balance'
    },
    changes: {
      'v2.0.0': [
        '删除了专门的矿工类',
        '所有用户都可以进行挖矿',
        '简化了系统架构',
        '用户类包含挖矿统计功能',
        '更新了相关API接口'
      ]
    }
  })
})

module.exports = {
  Transaction,
  Block,
  Blockchain,
  User,
  app,
  globalBlockchain,
  users
}