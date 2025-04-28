# dingtalk_authenticator.rb
class DingtalkAuthenticator < OAuth2BasicAuthenticator
  def name
    "dingtalk"
  end

  # 带缓存版本（生产环境使用）
  def fetch_user_details_with_cache(token, unionid)
    log "[钉钉认证] 开始获取用户详情(缓存版)，unionid: #{unionid}"

    corp_token = cached_corp_access_token
    return log_failure("企业Token获取失败") unless corp_token

    userid = cached_userid_lookup(corp_token, unionid)
    return log_failure("UserID查询失败") unless userid

    user_details = cached_user_details(corp_token, userid)
    return log_failure("用户详情获取失败") unless user_details

    parse_details(user_details).tap do |result|
      log "[钉钉认证] 用户详情获取成功: #{result.inspect}"
    end
  end

  # 无缓存版本（调试使用）
  def fetch_user_details_without_cache(token, unionid)
    log "[钉钉认证] 开始获取用户详情(无缓存版)，unionid: #{unionid}"

    corp_token = uncached_corp_access_token
    return log_failure("企业Token获取失败") unless corp_token

    userid = uncached_userid_lookup(corp_token, unionid)
    return log_failure("UserID查询失败") unless userid

    user_details = uncached_user_details(corp_token, userid)
    return log_failure("用户详情获取失败") unless user_details

    parse_details(user_details).tap do |result|
      log "[钉钉认证] 用户详情获取完成: #{result.inspect}"
    end
  end

  # 根据配置选择模式
  def fetch_user_details(token, unionid)
    if SiteSetting.dingtalk_enable_cache
      fetch_user_details_with_cache(token, unionid)
    else
      fetch_user_details_without_cache(token, unionid)
    end
  end

  private

  #===== 带缓存方法 =====
  def cached_corp_access_token
    cache_key = "dingtalk_corp_token_v2_#{SiteSetting.oauth2_client_id}"

    Discourse.cache.fetch(cache_key, expires_in: 7100) do
      log "[缓存] 企业Token缓存未命中，重新获取"
      uncached_corp_access_token
    end
  end

  def cached_userid_lookup(corp_token, unionid)
    cache_key = "dingtalk_unionid_mapping_#{unionid}"

    Discourse.cache.fetch(cache_key, expires_in: 86400) do
      log "[缓存] UnionID映射缓存未命中，重新查询"
      uncached_userid_lookup(corp_token, unionid)
    end
  end

  def cached_user_details(corp_token, userid)
    cache_key = "dingtalk_user_details_#{userid}"

    Discourse.cache.fetch(cache_key, expires_in: 3600) do
      log "[缓存] 用户详情缓存未命中，重新获取"
      uncached_user_details(corp_token, userid)
    end
  end

  #===== 无缓存方法 =====
  def uncached_corp_access_token
    log "[HTTP] 请求企业Token | AppKey: #{SiteSetting.oauth2_client_id}"

    response = Faraday.post(
      "https://api.dingtalk.com/v1.0/oauth2/accessToken", # 最新API地址
      {
        appKey: SiteSetting.oauth2_client_id,
        appSecret: SiteSetting.oauth2_client_secret
      }.to_json,
      {
        "Content-Type" => "application/json",
        "Accept" => "application/json"
      }
    )

    log_response(response, "企业Token")
    JSON.parse(response.body)["accessToken"] rescue nil
  end

  def uncached_userid_lookup(corp_token, unionid)
    log "[HTTP] 查询UserID | UnionID: #{unionid}"

    response = Faraday.post(
      "https://api.dingtalk.com/v1.0/contact/users/unionId/get", # 最新API地址
      { unionId: unionid }.to_json,
      {
        "Content-Type" => "application/json",
        "x-acs-dingtalk-access-token" => corp_token
      }
    )

    log_response(response, "UserID查询")
    JSON.parse(response.body)["userId"] rescue nil
  end

  def uncached_user_details(corp_token, userid)
    log "[HTTP] 获取用户详情 | UserID: #{userid}"

    response = Faraday.get(
      "https://api.dingtalk.com/v1.0/contact/users/#{userid}", # 最新API地址
      nil,
      {
        "x-acs-dingtalk-access-token" => corp_token
      }
    )

    log_response(response, "用户详情")
    JSON.parse(response.body) rescue nil
  end

  #===== 通用方法 =====
  def parse_details(data)
    {
      user_id: data.dig("unionId"),
      username: data.dig("nick"),
      name: data.dig("name"),
      email: data.dig("email") || fallback_email(data),
      avatar: data.dig("avatarUrl")
    }.tap do |result|
      result[:email_verified] = email_verified?(result)
    end
  end

  def fallback_email(data)
    "#{data['unionId']}@#{SiteSetting.oauth2_email_domain}"
  end

  def email_verified?(details)
    details[:email].present? && details[:email].include?("@")
  end

  def log_response(response, api_name)
    log <<~LOG
      [HTTP响应] #{api_name} API
      状态码: #{response.status}
      响应头: #{response.headers.to_h.to_json}
      响应体: #{response.body.inspect}
    LOG
  end

  def log_failure(message)
    log "[错误] #{message}"
    nil
  end
end