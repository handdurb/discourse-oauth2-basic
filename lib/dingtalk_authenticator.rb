# dingtalk_authenticator.rb
class DingtalkAuthenticator < OAuth2BasicAuthenticator


  # def register_middleware(omniauth)
  #   omniauth.provider :oauth2_basic,
  #                     name: name,
  #                     setup: lambda { |env|
  #                       opts = env["omniauth.strategy"].options
  #
  #                       # # 强制启用 Faraday 日志中间件
  #                       # opts[:client_options][:connection_build] = lambda do |builder|
  #                       #   if SiteSetting.oauth2_debug_auth
  #                       #     builder.response :logger, Rails.logger, {
  #                       #       bodies: true,
  #                       #       formatter: OAuth2FaradayFormatter # 使用自定义格式化类
  #                       #     }
  #                       #   end
  #                       #   builder.adapter FinalDestination::FaradayAdapter
  #                       # end
  #
  #                       # 强制使用钉钉参数命名
  #                       opts[:client_id] = SiteSetting.oauth2_client_id # 使用独立配置项
  #                       opts[:client_secret] = SiteSetting.oauth2_client_secret
  #
  #                       opts[:client_options] = {
  #                         site: "https://api.dingtalk.com",
  #                         authorize_url: "/oauth2/auth",
  #                         token_url: "/v1.0/oauth2/userAccessToken",
  #                         auth_scheme: :request_body
  #                       }
  #
  #                       opts[:token_params] = {
  #                         headers: {
  #                           "Content-Type" => "application/json",
  #                           "X-Dingtalk-Isv" => "true"
  #                         },
  #                         body: {
  #                           clientId: opts[:client_id], # 使用驼峰命名
  #                           clientSecret: opts[:client_secret],
  #                           code: env.dig("rack.request.query_hash", "code"), # 安全访问
  #                           grantType: "authorization_code"
  #                         }.to_json
  #                       }
  #                     }
  # end
  # 核心认证流程
  def after_authenticate(auth, existing_account: nil)
    # 直接使用策略类获取的 token
    user_token = auth.dig(:credentials, :token)
    return auth_failed("Token缺失") unless user_token

    # 2. 获取基础用户信息（包含unionId）
    base_info = get_base_user_info(user_token)
    return auth_failed("基础信息获取失败") unless base_info
    unionid = base_info.dig("unionId")

    log "[钉钉] after_authenticate: 获取详细用户信息"
    # 3. 获取详细用户信息
    user_details = fetch_user_details(unionid)
    return auth_failed("用户详情获取失败") unless user_details

    # 4. 构建认证结果
    build_auth_result(user_details).tap do |result|
      log "[钉钉] 认证完成: #{result.inspect}"
    end
  end

  private

  # 获取用户访问令牌
  def get_user_access_token(code)
    log "[HTTP] 获取用户访问令牌 | code: #{code[0..3]}***"

    response = Faraday.post(
      "https://api.dingtalk.com/v1.0/oauth2/userAccessToken",
      {
        clientId: SiteSetting.oauth2_client_id,
        clientSecret: SiteSetting.oauth2_client_secret,
        code: code,
        grantType: "authorization_code"
      }.to_json,
      {
        "Content-Type" => "application/json",
        "Accept" => "application/json"
      }
    )

    log_response(response, "用户令牌")
    JSON.parse(response.body)["accessToken"] rescue nil
  end

  # 获取基础用户信息
  def get_base_user_info(user_token)
    log "[HTTP] 获取基础用户信息"

    return nil unless user_token

    response = Faraday.get(
      "https://api.dingtalk.com/v1.0/contact/users/me",
      nil,
      { "x-acs-dingtalk-access-token" => user_token }
    )

    return log_failure("请求失败: #{response.status}") unless response.success?

    JSON.parse(response.body) rescue nil
  end

  # 获取详细用户信息（带缓存控制）
  def fetch_user_details(unionid)
    if SiteSetting.dingtalk_enable_cache
      fetch_with_cache(unionid)
    else
      fetch_without_cache(unionid)
    end
  end

  # 带缓存版本
  def fetch_with_cache(unionid)
    cache_key = "dingtalk_user_#{unionid}"

    Discourse.cache.fetch(cache_key, expires_in: 3600) do
      log "[缓存] 用户详情缓存未命中，重新获取"
      fetch_corp_details(unionid)
    end
  end

  # 无缓存版本
  def fetch_without_cache(unionid)
    fetch_corp_details(unionid)
  end

  # 企业API获取详细信息
  def fetch_corp_details(unionid)
    log "[钉钉] fetch_corp_details"
    # 获取企业令牌
    corp_token = get_corp_access_token
    return log_failure("企业令牌获取失败") unless corp_token

    # 通过unionid获取userid
    userid = get_userid(corp_token, unionid)
    return log_failure("UserID查询失败") unless userid

    # 获取完整用户信息
    response = Faraday.get(
      "https://api.dingtalk.com/v1.0/contact/users/#{userid}",
      nil,
      {
        "x-acs-dingtalk-access-token" => corp_token
      }
    )

    return log_failure("用户详情请求失败") unless response.success?

    parse_details(JSON.parse(response.body))
  end

  # 获取企业访问令牌（带缓存）
  def get_corp_access_token
    cache_key = "dingtalk_corp_token_#{SiteSetting.oauth2_client_id}"

    Discourse.cache.fetch(cache_key, expires_in: 7100) do
      log "[缓存] 企业令牌缓存未命中，重新获取"
      response = Faraday.get(
        "https://oapi.dingtalk.com/gettoken",
        {
          appkey: SiteSetting.oauth2_client_id,
          appsecret: SiteSetting.oauth2_client_secret
        },
        {}
      )

      log_response(response, "企业令牌接口")
      JSON.parse(response.body)["access_token"] rescue nil  # 注意字段名可能是 "access_token"
    end
  end

  # 通过unionid获取userid
  def get_userid(corp_token, unionid)
    response = Faraday.post(
      "https://api.dingtalk.com/v1.0/contact/users/unionId/get",
      { unionId: unionid }.to_json,
      {
        "Content-Type" => "application/json",
        "x-acs-dingtalk-access-token" => corp_token
      }
    )

    JSON.parse(response.body).dig("result", "userId") rescue nil
  end

  # 解析用户详情
  def parse_details(data)
    return {} unless data.is_a?(Hash)

    {
      user_id: data.dig("unionId"),
      username: data["nick"] || data["name"] || "钉钉用户",
      email: data["email"] || "#{data['unionId']}@#{SiteSetting.oauth2_email_domain}",
      avatar: data["avatarUrl"],
      email_verified: data["email"].present?
    }.compact
  end

  # 构建认证结果
  def build_auth_result(details)
    Auth::Result.new.tap do |result|
      result.email = details[:email]
      result.email_valid = details[:email_verified]
      result.username = details[:username]
      result.name = details[:name]
      result.extra_data = { unionid: details[:user_id] }
    end
  end

  # 统一日志方法
  def log_response(response, api_name)
    log <<~LOG
      [API响应] #{api_name}
      状态码: #{response.status}
      响应头: #{response.headers.to_json}
      响应体: #{response.body[0..200]}...
    LOG
  end

  def auth_failed(reason)
    log "[错误] 认证失败: #{reason}"
    result = Auth::Result.new
    result.failed = true
    result.failed_reason = reason
    result
  end
end