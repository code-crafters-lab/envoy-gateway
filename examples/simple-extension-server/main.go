// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	extauthv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	pb "github.com/envoyproxy/gateway/proto/extension"
)

func main() {
	app := cli.App{
		Name:           "extension-server",
		Version:        "0.0.1",
		Description:    "Example Envoy Gateway Extension Server",
		DefaultCommand: "server",
		Commands: []*cli.Command{
			{
				Name:   "server",
				Usage:  "runs the Extension Server",
				Before: handleSignals,
				Action: startExtensionServer,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "host",
						Usage:       "the host on which to listen",
						DefaultText: "0.0.0.0",
						Value:       "0.0.0.0",
					},
					&cli.IntFlag{
						Name:        "port",
						Usage:       "the port on which to listen",
						DefaultText: "5005",
						Value:       5005,
					},
					&cli.StringFlag{
						Name:        "log-level",
						Usage:       "the log level, should be one of Debug/Info/Warn/Error",
						DefaultText: "Info",
						Value:       "Info",
					},
				},
			},
		},
	}
	app.Run(os.Args)
}

var grpcServer *grpc.Server

func handleSignals(cCtx *cli.Context) error {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGQUIT)
	go func() {
		for range c {
			if grpcServer != nil {
				grpcServer.Stop()
				os.Exit(0)
			}
		}
	}()
	return nil
}

func startExtensionServer(cCtx *cli.Context) error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cCtx.String("log-level"))); err != nil {
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))
	address := net.JoinHostPort(cCtx.String("host"), cCtx.String("port"))
	logger.Info("Starting the extension server", slog.String("host", address))
	lis, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	var opts []grpc.ServerOption
	grpcServer = grpc.NewServer(opts...)
	sig := make(chan int, 1)
	pb.RegisterEnvoyGatewayExtensionServer(grpcServer, New(logger, sig))
	return grpcServer.Serve(lis)
}

type Server struct {
	pb.UnimplementedEnvoyGatewayExtensionServer
	sig chan int
	log *slog.Logger
}

func New(logger *slog.Logger, sig chan int) *Server {
	return &Server{
		log: logger,
		sig: sig,
	}
}

func (s *Server) PostRouteModify(ctx context.Context, req *pb.PostRouteModifyRequest) (*pb.PostRouteModifyResponse, error) {
	s.log.Info("PostRouteModify callback was invoked")

	return &pb.PostRouteModifyResponse{
		Route: req.Route,
	}, nil
}

func (s *Server) PostVirtualHostModify(ctx context.Context, req *pb.PostVirtualHostModifyRequest) (*pb.PostVirtualHostModifyResponse, error) {
	s.log.Info("PostVirtualHostModify callback was invoked")

	if strings.Contains(req.VirtualHost.Name, "fail") {
		s.log.Info("PostVirtualHostModify returning unavailable error")
		return nil, status.Error(codes.Unavailable, "Service is currently unavailable")
	} else {
		s.log.Info("PostVirtualHostModify sending response")
		if len(req.VirtualHost.Domains) > 0 {
			req.VirtualHost.Domains = append(req.VirtualHost.Domains, fmt.Sprintf("%s.extserver", req.VirtualHost.Domains[0]))
		}
		return &pb.PostVirtualHostModifyResponse{
			VirtualHost: req.VirtualHost,
		}, nil
	}
}

func (s *Server) PostHTTPListenerModify(ctx context.Context, req *pb.PostHTTPListenerModifyRequest) (*pb.PostHTTPListenerModifyResponse, error) {
	s.log.Info("postHTTPListenerModify callback was invoked")

	filterChains := req.Listener.GetFilterChains()
	defaultFC := req.Listener.DefaultFilterChain
	if defaultFC != nil {
		filterChains = append(filterChains, defaultFC)
	}
	for _, currChain := range filterChains {
		httpConManager, hcmIndex, err := findHCM(currChain)
		if err != nil {
			s.log.Error("failed to find an HCM in the current chain", slog.Any("error", err))
			continue
		}
		// If a basic ext auth filter already exists, update it.
		extAuth, extIndex, err := findExtAuthFilter(httpConManager.HttpFilters)
		if extIndex != -1 {
			switch svc := extAuth.Services.(type) {
			case *extauthv3.ExtAuthz_GrpcService:
				// svc 是 *ext_authz_v3.ExtAuthz_GrpcService 类型
				// 我们可以安全地访问它的 GrpcService 字段
				grpcService := svc.GrpcService
				if grpcService.InitialMetadata == nil {
					grpcService.InitialMetadata = make([]*corev3.HeaderValue, 0)
				}
				grpcService.InitialMetadata = append(grpcService.InitialMetadata,
					&corev3.HeaderValue{Key: "x-target-cluster", Value: "%UPSTREAM_CLUSTER%"},
					&corev3.HeaderValue{Key: "x-target-service", Value: "%CLUSTER_METADATA(annotations:service)%"},
				)
			// Update the ext auth filter
			case *extauthv3.ExtAuthz_HttpService:

			}
		}
		s.log.Info("extAuth filter not found, creating a new one", extAuth)

		anyEAFilter, _ := anypb.New(extAuth)
		if extIndex > -1 {
			httpConManager.HttpFilters[extIndex].ConfigType = &hcm.HttpFilter_TypedConfig{
				TypedConfig: anyEAFilter,
			}
		}
		// Write the updated HCM back to the filter chain
		anyConnectionMgr, _ := anypb.New(httpConManager)
		currChain.Filters[hcmIndex].ConfigType = &listenerv3.Filter_TypedConfig{
			TypedConfig: anyConnectionMgr,
		}
	}

	return &pb.PostHTTPListenerModifyResponse{
		Listener: req.Listener,
	}, nil
}

func findExtAuthFilter(filters []*hcm.HttpFilter) (*extauthv3.ExtAuthz, int, error) {
	for i, filter := range filters {
		if strings.HasPrefix(filter.Name, "envoy.filters.http.ext_authz") {
			extAuthz := new(extauthv3.ExtAuthz)
			if err := filter.GetTypedConfig().UnmarshalTo(extAuthz); err != nil {
				return nil, -1, err
			}
			return extAuthz, i, nil
		}
	}
	return nil, -1, nil
}

// Tries to find an HTTP connection manager in the provided filter chain.
func findHCM(filterChain *listenerv3.FilterChain) (*hcm.HttpConnectionManager, int, error) {
	for filterIndex, filter := range filterChain.Filters {
		if filter.Name == wellknown.HTTPConnectionManager {
			hcm := new(hcm.HttpConnectionManager)
			if err := filter.GetTypedConfig().UnmarshalTo(hcm); err != nil {
				return nil, -1, err
			}
			return hcm, filterIndex, nil
		}
	}
	return nil, -1, fmt.Errorf("unable to find HTTPConnectionManager in FilterChain: %s", filterChain.Name)
}

func (s *Server) PostTranslateModify(ctx context.Context, req *pb.PostTranslateModifyRequest) (*pb.PostTranslateModifyResponse, error) {
	s.log.Info("PostTranslateModify callback was invoked")

	for _, cluster := range req.GetClusters() {
		if strings.Contains(cluster.Name, "basic-api") {
			service := &structpb.Value{
				Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"id":          {Kind: &structpb.Value_StringValue{StringValue: "0001"}},
						"name":        {Kind: &structpb.Value_StringValue{StringValue: "basic-api"}},
						"version":     {Kind: &structpb.Value_StringValue{StringValue: "v1.0.0"}},
						"environment": {Kind: &structpb.Value_StringValue{StringValue: "dev"}},
					},
				}},
			}
			m := map[string]*structpb.Struct{}
			m["annotations"] = &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"service": service,
				},
			}

			cluster.Metadata.FilterMetadata = m

		}
	}
	return &pb.PostTranslateModifyResponse{
		Secrets:  req.Secrets,
		Clusters: req.Clusters,
	}, nil
}
