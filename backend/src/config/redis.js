const { createClient } = require("redis");

let redisClient;

const connectRedis = async () => {
  redisClient =await createClient({ url: process.env.REDIS_URL });

  redisClient.on("error", (err) =>
    console.error("Redis error:", err.message)
  );

  await redisClient.connect();
  console.log("Redis connected");
};

const getRedis = () => {
  if (!redisClient) throw new Error("Redis not initialised");
  return redisClient;
};

module.exports = { connectRedis, getRedis };
